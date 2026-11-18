//! The receiver's HTTP transport for the same read handler as the local Viewer.
use super::{Connection, Head, Next};
use crate::{enrollment::Registry, read_tokens::valid_id};
use ring::{hmac, rand::SecureRandom};
use semon_sessions::{
    Options, ReceivedMachines, Refresh, VIEWER_HOME_BODY_LIMIT, VIEWER_SESSION_COOKIE, ViewerCore,
    ViewerReply, viewer_session_cookie, viewer_token_parameter,
};
use std::{
    io,
    path::{Path, PathBuf},
};

pub(super) struct PublicOrigin {
    host: String,
    origin: String,
    secure: bool,
}

impl PublicOrigin {
    pub(super) fn parse(raw: &str) -> Result<Self, String> {
        let invalid =
            || "--public-url requires an HTTPS origin (HTTP is allowed on loopback)".to_owned();
        let origin = raw.strip_suffix('/').unwrap_or(raw);
        let (scheme, host) = origin.split_once("://").ok_or_else(invalid)?;
        if host.is_empty()
            || host.contains(['/', '\\', '@', '?', '#', '%'])
            || !host.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(invalid());
        }
        let url = reqwest::Url::parse(origin).map_err(|_| invalid())?;
        let loopback = url.host_str().is_some_and(|name| {
            name == "localhost"
                || name
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if scheme != "https" && (scheme != "http" || !loopback) {
            return Err(invalid());
        }
        let origin = url.origin().ascii_serialization();
        let (_, host) = origin.split_once("://").ok_or_else(invalid)?;
        Ok(Self {
            host: host.into(),
            origin,
            secure: scheme == "https",
        })
    }
}

pub(super) struct Viewer {
    dir: PathBuf,
    core: ViewerCore,
    public: Option<PublicOrigin>,
    loopback: [(String, String); 3],
    secure: bool,
    session_key: hmac::Key,
}

impl Viewer {
    pub(super) fn new(
        dir: &Path,
        port: u16,
        tls: bool,
        public: Option<PublicOrigin>,
    ) -> Result<Self, String> {
        let mut key = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| "cannot initialize Viewer session key")?;
        let session_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        let mut core = ViewerCore::with_received(
            Vec::new(),
            ReceivedMachines::new(
                dir,
                &Options {
                    all: true,
                    ..Options::default()
                },
            ),
        );
        core.set_refresh(Refresh::Background);
        let scheme = if tls { "https" } else { "http" };
        let loopback = ["127.0.0.1", "localhost", "[::1]"].map(|name| {
            let host = if (tls && port == 443) || (!tls && port == 80) {
                name.to_owned()
            } else {
                format!("{name}:{port}")
            };
            let origin = format!("{scheme}://{host}");
            (host, origin)
        });
        Ok(Self {
            dir: dir.into(),
            core,
            secure: tls || public.as_ref().is_some_and(|p| p.secure),
            public,
            loopback,
            session_key,
        })
    }

    fn allows(&self, host: &str, origin: Option<&str>) -> bool {
        let matches = |allowed_host: &str, allowed_origin: &str| {
            host == allowed_host && origin.is_none_or(|origin| origin == allowed_origin)
        };
        self.public
            .as_ref()
            .is_some_and(|public| matches(&public.host, &public.origin))
            || self
                .loopback
                .iter()
                .any(|(host, origin)| matches(host, origin))
    }

    fn session(&self, id: &str) -> String {
        let tag = hmac::sign(&self.session_key, id.as_bytes());
        viewer_session_cookie(&format!("{id}.{}", hex::encode(tag.as_ref())), self.secure)
    }

    fn valid_session(&self, registry: &Registry, cookies: &str) -> bool {
        let mut values = cookies.split(';').filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == VIEWER_SESSION_COOKIE).then_some(value)
        });
        let Some((id, tag)) = values.next().and_then(|value| value.split_once('.')) else {
            return false;
        };
        if values.next().is_some() || !valid_id(id) || !valid_id(tag) {
            return false;
        }
        let tag = hex::decode(tag).expect("validated hex");
        hmac::verify(&self.session_key, id.as_bytes(), &tag).is_ok()
            && registry.read_token_active(id)
    }

    pub(super) fn answer(&self, connection: &mut Connection, head: &Head) -> Next {
        let _ = self.respond(connection, head);
        Next::Close
    }

    fn respond(&self, connection: &mut Connection, head: &Head) -> io::Result<()> {
        let forbidden = |connection: &mut Connection| error(connection, 403, "Forbidden");
        let Ok(Some(host)) = head.viewer_header("host") else {
            return forbidden(connection);
        };
        let Ok(origin) = head.viewer_header("origin") else {
            return forbidden(connection);
        };
        if !self.allows(host, origin) {
            return forbidden(connection);
        }
        let (path, query) = head.target.split_once('?').unwrap_or((&head.target, ""));
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('\\')
            || head.target.contains('#')
            || !head.target.bytes().all(|b| b.is_ascii_graphic())
        {
            return error(connection, 400, "Invalid request target");
        }
        let home_post = head.method == "POST" && path == "/api/viewer/home";
        if !home_post && !matches!(head.method.as_str(), "GET" | "HEAD") {
            return error(connection, 405, "Method not allowed");
        }
        if head.transfer_encoding || (!home_post && head.content_length.unwrap_or(0) != 0) {
            return error(connection, 400, "Invalid Viewer request framing");
        }
        if head.expect_other || (!home_post && head.expect_continue) {
            return error(connection, 417, "Unsupported expectation");
        }
        let Ok(registry) = Registry::read_current(&self.dir) else {
            return forbidden(connection);
        };
        let mut bootstrap = query.split('&').filter(|part| viewer_token_parameter(part));
        if let Some(part) = bootstrap.next() {
            if head.method != "GET" || bootstrap.next().is_some() || head.authorization.is_some() {
                return forbidden(connection);
            }
            let Some(id) = part
                .strip_prefix("t=")
                .and_then(|value| registry.read_token_id(value))
            else {
                return forbidden(connection);
            };
            let clean = query
                .split('&')
                .filter(|part| !viewer_token_parameter(part))
                .collect::<Vec<_>>()
                .join("&");
            let location = if clean.is_empty() {
                path.to_owned()
            } else {
                format!("{path}?{clean}")
            };
            let cookie = self.session(id);
            return reply(
                connection,
                303,
                "text/plain; charset=utf-8",
                &[],
                &semon_sessions::SECURITY_HEADERS,
                &[("Location", &location), ("Set-Cookie", &cookie)],
            );
        }
        let authorized = if let Some(bearer) = &head.authorization {
            bearer
                .strip_prefix("Bearer ")
                .and_then(|secret| registry.read_token_id(secret))
                .is_some()
        } else {
            (!home_post || origin.is_some())
                && head.viewer_header("cookie").is_ok_and(|cookies| {
                    cookies.is_some_and(|cookies| self.valid_session(&registry, cookies))
                })
        };
        if !authorized {
            return forbidden(connection);
        }
        drop(registry);
        let bytes = if home_post {
            let Some(length) = head.content_length else {
                return error(connection, 411, "A Content-Length is required");
            };
            if length > VIEWER_HOME_BODY_LIMIT as u64 {
                return error(connection, 413, "The Viewer request body is too large");
            }
            if head.content_type.is_none() {
                return error(connection, 400, "A Content-Type is required");
            }
            if head.expect_continue {
                connection.send(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            }
            Some(connection.read_body(length as usize)?)
        } else {
            None
        };
        let Ok(etag) = head.viewer_header("if-none-match") else {
            return error(connection, 400, "Multiple If-None-Match headers");
        };
        let answer = self
            .core
            .respond_viewer_read(path, query, etag, bytes.as_deref());
        respond_read(connection, &answer)
    }
}

fn respond_read(connection: &mut Connection, answer: &ViewerReply) -> io::Result<()> {
    let mut headers = Vec::new();
    if let Some(etag) = &answer.etag {
        headers.push(("ETag", etag.as_str()));
    }
    reply(
        connection,
        answer.status,
        answer.content_type,
        &answer.body,
        answer.headers(),
        &headers,
    )
}

pub(super) fn error(connection: &mut Connection, status: u16, body: &str) -> io::Result<()> {
    reply(
        connection,
        status,
        "text/plain; charset=utf-8",
        body.as_bytes(),
        &semon_sessions::SECURITY_HEADERS,
        &[],
    )
}

fn reply(
    connection: &mut Connection,
    status: u16,
    content_type: &str,
    body: &[u8],
    security: &[(&str, &str)],
    extra: &[(&str, &str)],
) -> io::Result<()> {
    use std::fmt::Write as _;
    let phrase = tiny_http::StatusCode(status).default_reason_phrase();
    let mut head = format!(
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in security.iter().chain(extra) {
        // Received attachments also stay off disk caches after a token is revoked.
        let value = if *name == "Cache-Control" {
            "no-store"
        } else {
            value
        };
        write!(head, "{name}: {value}\r\n").expect("write to String");
    }
    head.push_str("\r\n");
    connection.send_parts(&[
        head.as_bytes(),
        if connection.head_only { &[] } else { body },
    ])
}
