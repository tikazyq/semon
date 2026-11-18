//! Read-only Viewer embedded in the receiver dispatcher, without another listener.
#[cfg(test)]
#[path = "serve_viewer_tests.rs"]
mod tests;
use super::*;
use ring::hmac;
use semon_sessions as viewer;
use semon_sessions::{Options, ReceivedMachines, Refresh, ViewerCore};

pub(super) struct Viewer {
    core: ViewerCore,
    dir: PathBuf,
    port: u16,
    public: Option<(String, String)>,
    secure: bool,
    cookie_key: hmac::Key,
}

impl Viewer {
    pub(super) fn new(
        dir: &Path,
        address: SocketAddr,
        public_url: Option<&str>,
        tls: bool,
    ) -> Result<Self, String> {
        let public = public_url.map(|raw| {
            let url = reqwest::Url::parse(raw).map_err(|_| "invalid --public-url")?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
                || !url.username().is_empty() || url.password().is_some()
                || url.path() != "/" || url.query().is_some() || url.fragment().is_some()
            { return Err("--public-url requires an HTTP(S) origin without credentials, path, query or fragment"); }
            let origin = url.origin().ascii_serialization();
            let host = origin.split_once("://").expect("HTTP origin").1.to_owned();
            Ok((host, origin))
        }).transpose().map_err(str::to_owned)?;
        let secure = public
            .as_ref()
            .map_or(tls, |(_, origin)| origin.starts_with("https://"));
        let options = Options {
            all: true,
            cache: dir.join("viewer/index.json"),
            ..Options::default()
        };
        let mut core = ViewerCore::with_received(vec![], ReceivedMachines::new(dir, &options));
        core.set_refresh(Refresh::Background);
        let key = crate::credentials::Secret::generate().map_err(|e| e.to_string())?;
        Ok(Self {
            core,
            dir: dir.into(),
            port: address.port(),
            public,
            secure,
            cookie_key: hmac::Key::new(hmac::HMAC_SHA256, &key.hash()),
        })
    }

    fn allowed(&self, head: &Head) -> bool {
        let Some(host) = head.host.as_deref() else {
            return false;
        };
        let loopback = [
            format!("127.0.0.1:{}", self.port),
            format!("localhost:{}", self.port),
            format!("[::1]:{}", self.port),
        ];
        let public = self
            .public
            .as_ref()
            .is_some_and(|(allowed, _)| host == allowed);
        if !public && !loopback.iter().any(|h| h == host) {
            return false;
        }
        head.origin.as_deref().is_none_or(|origin| {
            self.public
                .as_ref()
                .is_some_and(|(_, allowed)| origin == allowed)
                || loopback.iter().any(|h| {
                    origin
                        == format!(
                            "{}://{h}",
                            if self.secure && self.public.is_none() {
                                "https"
                            } else {
                                "http"
                            }
                        )
                })
        })
    }

    fn cookie(&self, id: &str) -> String {
        format!(
            "{id}.{}",
            hex::encode(hmac::sign(&self.cookie_key, id.as_bytes()).as_ref())
        )
    }

    fn cookie_id<'a>(&self, cookie: &'a str) -> Option<&'a str> {
        let (id, tag) = cookie.split_once('.')?;
        let tag = hex::decode(tag).ok()?;
        hmac::verify(&self.cookie_key, id.as_bytes(), &tag).ok()?;
        Some(id)
    }

    fn reply(
        &self,
        connection: &mut Connection,
        status: u16,
        content_type: &str,
        body: &[u8],
        extra: &[(&str, &str)],
    ) {
        let mut head = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
            reason(status),
            body.len()
        );
        for (name, value) in viewer::SECURITY_HEADERS
            .iter()
            .copied()
            .chain(extra.iter().copied())
        {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        connection.stream.timed().deadline = Instant::now() + connection.limits.write;
        let _ = connection
            .stream
            .write_all(head.as_bytes())
            .and_then(|()| {
                if connection.head_only {
                    Ok(())
                } else {
                    connection.stream.write_all(body)
                }
            })
            .and_then(|()| connection.stream.flush());
    }

    pub(super) fn answer(&self, slot: &mut Slot, connection: &mut Connection, head: &Head) -> Next {
        // Classify before doing read work; Viewer requests never occupy the peer's
        // push allowance, and may use at most half of all connection slots.
        connection.limits.linger = Duration::ZERO;
        if !slot.admit_viewer() {
            return Next::Close;
        }
        let deny = |status, body: &[u8], connection: &mut Connection| {
            self.reply(connection, status, "text/plain", body, &[]);
            Next::Close
        };
        if !self.allowed(head) {
            return deny(403, b"Forbidden", connection);
        }
        let (path, query) = head.target.split_once('?').unwrap_or((&head.target, ""));
        if !path.starts_with('/') || path.starts_with("//") || path.contains(['\\', '#']) {
            return deny(400, b"Invalid target", connection);
        }
        let post = head.method == "POST" && path == "/api/viewer/home";
        if head.method != "GET" && !post {
            return deny(405, b"Method not allowed", connection);
        }
        if head.transfer_encoding
            || head.expect_other
            || head.content_length.unwrap_or(0) > if post { 512 * 1024 } else { 0 }
        {
            return deny(400, b"Invalid framing", connection);
        }
        let Ok(registry) = crate::enrollment::Registry::read_current(&self.dir) else {
            return deny(503, b"Read authorization unavailable", connection);
        };
        // Decode names too: an encoded or duplicate credential cannot survive
        // bootstrap as an ordinary routing argument.
        let pairs: Vec<_> = query.split('&').filter(|part| !part.is_empty()).collect();
        let credentials: Vec<_> = pairs
            .iter()
            .filter(|part| {
                let name = part.split_once('=').map_or(**part, |(name, _)| name);
                name == "t" || name.eq_ignore_ascii_case("%74")
            })
            .collect();
        if !credentials.is_empty() {
            if post
                || credentials.len() != 1
                || !credentials[0].starts_with("t=")
                || head.authorization.is_some()
            {
                return deny(403, b"Forbidden", connection);
            }
            let Some(token) = registry.read_token(&credentials[0][2..]) else {
                return deny(403, b"Forbidden", connection);
            };
            let query = pairs
                .iter()
                .filter(|p| !p.starts_with("t="))
                .copied()
                .collect::<Vec<_>>()
                .join("&");
            let location = format!("{path}{}{}", if query.is_empty() { "" } else { "?" }, query);
            let cookie = format!(
                "semon_session={}; HttpOnly; SameSite=Strict; Path=/{}",
                self.cookie(&token.id),
                if self.secure { "; Secure" } else { "" }
            );
            self.reply(
                connection,
                303,
                "text/plain",
                b"",
                &[("Location", &location), ("Set-Cookie", &cookie)],
            );
            return Next::Close;
        }
        let authorized = if let Some(auth) = head.authorization.as_deref() {
            auth.strip_prefix("Bearer ")
                .and_then(|raw| registry.read_token(raw))
                .is_some()
        } else {
            let cookies: Vec<_> = head
                .cookie
                .as_deref()
                .unwrap_or("")
                .split(';')
                .filter_map(|part| part.trim().strip_prefix("semon_session="))
                .collect();
            cookies.len() == 1
                && self.cookie_id(cookies[0]).is_some_and(|id| {
                    registry
                        .read_tokens
                        .iter()
                        .any(|t| t.id == id && t.revoked_at.is_none())
                })
        };
        if !authorized {
            return deny(401, b"Read token required", connection);
        }
        if post && head.authorization.is_none() && head.origin.is_none() {
            return deny(403, b"Origin required", connection);
        }
        if head.expect_continue && connection.send(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
            return Next::Close;
        }
        let Ok(body) = connection.read_body(head.content_length.unwrap_or(0) as usize) else {
            return deny(408, b"Request timed out", connection);
        };
        let reply = viewer::handle_authorized(
            &self.core,
            &head.method,
            path,
            query,
            &body,
            head.if_none_match.as_deref(),
        );
        let extra = reply
            .etag
            .as_deref()
            .map(|etag| vec![("ETag", etag)])
            .unwrap_or_default();
        self.reply(
            connection,
            reply.status,
            reply.content_type,
            &reply.body,
            &extra,
        );
        Next::Close
    }
}
