#![cfg(feature = "asi-query")]

#[path = "../../../tests/support/native_home_cli.rs"]
mod fixture;

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

use semon_asi::{Manifest, Store};
use serde_json::{Value, json};

fn store() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("state/analytics-store");
    Store::open(&root).unwrap();
    std::fs::write(
        root.join("analytics/manifest.json"),
        serde_json::to_vec(&Manifest::empty()).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("state/analytics-namespace"),
        format!("origin-{}\n", "0".repeat(64)),
    )
    .unwrap();
    dir
}

fn cli_args(cache: PathBuf) -> Vec<String> {
    ["--cache".to_owned(), cache.to_string_lossy().into_owned()]
        .into_iter()
        .collect()
}

fn cli(args: &[&str], cache: PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_semon"))
        .args(args)
        .args(cli_args(cache))
        .output()
        .unwrap()
}

struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    replies: Receiver<String>,
}

impl Server {
    fn start(cache: PathBuf) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_semon"))
            .arg("mcp")
            .args(cli_args(cache))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, replies) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            stdin: child.stdin.take(),
            child,
            replies,
        }
    }

    fn request(&mut self, value: Value) -> Value {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{value}").unwrap();
        stdin.flush().unwrap();
        let reply = self.replies.recv_timeout(Duration::from_secs(30)).unwrap();
        serde_json::from_str(&reply).unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

fn content(reply: &Value) -> (Value, bool) {
    let result = &reply["result"];
    (
        serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap(),
        result["isError"].as_bool().unwrap(),
    )
}

#[test]
fn cli_sql_json_tsv_and_typed_errors() {
    let dir = store();
    let cache = dir.path().join("state/index.json");
    let output = cli(
        &["query", "sql", "SELECT ? AS value", "--params", "[42]"],
        cache.clone(),
    );
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["rows"], json!([[42]]));

    let output = cli(
        &[
            "query",
            "sql",
            "SELECT 'a\tb\nc' AS \"d\te\nf\"",
            "--format",
            "tsv",
        ],
        cache.clone(),
    );
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "d e f\na b c\n");

    let output = cli(&["query", "schema"], cache.clone());
    assert!(output.status.success());
    let schema: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(schema["tables"].as_array().is_some());
    assert_eq!(schema["data_notice"], semon_asi::query::DATA_NOTICE);

    let output = cli(&["query", "sql", "SELECT getenv('HOME')"], cache.clone());
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["error"]["code"], "not_allowed");

    for arguments in [
        vec!["query", "sql"],
        vec!["query", "sql", "SELECT 1", "--limit", "nope"],
        vec!["query", "sql", "SELECT 1", "--params", "["],
        vec!["query", "sql", "SELECT 1", "--params", "[{}]"],
        vec!["query", "sql", "SELECT 1", "--machine", "/received/machine"],
        vec!["query", "schema", "--machine", "/received/machine"],
        vec!["query", "sql", "SELECT 1", "--claude-home", "/other/home"],
    ] {
        let output = cli(&arguments, cache.clone());
        assert!(!output.status.success(), "{arguments:?}");
        let error: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(error["error"]["code"], "invalid_argument", "{arguments:?}");
    }
}

#[test]
fn mcp_advertises_asi_tools_and_serves_schema_resource() {
    let dir = store();
    let mut server = Server::start(dir.path().join("state/index.json"));
    let initialized = server.request(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}));
    assert_eq!(
        initialized["result"]["capabilities"]["resources"]["subscribe"],
        false
    );
    let listed = server.request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let tools = listed["result"]["tools"].as_array().unwrap();
    let names: Vec<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"sql"));
    assert!(names.contains(&"schema"));
    assert!(names.contains(&"search"));
    assert!(names.contains(&"view"));
    assert!(!names.contains(&"find"));
    let sql = tools.iter().find(|tool| tool["name"] == "sql").unwrap();
    assert_eq!(sql["inputSchema"]["required"], json!(["query"]));
    assert_eq!(sql["inputSchema"]["additionalProperties"], false);
    assert_eq!(sql["inputSchema"]["properties"]["params"]["type"], "array");

    let resources = server.request(json!({"jsonrpc":"2.0","id":3,"method":"resources/list"}));
    assert_eq!(
        resources["result"]["resources"][0]["uri"],
        "semon://asi/schema"
    );
    let resource = server.request(json!({"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"semon://asi/schema"}}));
    let schema: Value =
        serde_json::from_str(resource["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert!(schema["tables"].as_array().is_some());
    assert_eq!(schema["data_notice"], semon_asi::query::DATA_NOTICE);

    let schema = server
        .request(json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"schema"}}));
    let (schema, failed) = content(&schema);
    assert!(!failed);
    assert!(schema["tables"].as_array().is_some());
    assert_eq!(schema["data_notice"], semon_asi::query::DATA_NOTICE);
    let schema = server.request(json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"schema","arguments":{"table":"dim_session"}}}));
    let (schema, failed) = content(&schema);
    assert!(!failed);
    assert_eq!(schema["table"]["name"], "dim_session");
    assert_eq!(schema["data_notice"], semon_asi::query::DATA_NOTICE);

    let reply = server
        .request(json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sql"}}));
    let (error, failed) = content(&reply);
    assert!(failed);
    assert_eq!(error["error"]["code"], "invalid_argument");

    let reply = server.request(json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"sql","arguments":{"query":"SELECT getenv('HOME')"}}}));
    let (error, failed) = content(&reply);
    assert!(failed);
    assert_eq!(error["error"]["code"], "not_allowed");
}

#[test]
fn origin_body_queries_through_cli_and_mcp() {
    let fixture = fixture::Fixture::new();
    let cache = fixture.root.join("state/index.json");
    let materialize = || {
        fixture
            .command(env!("CARGO_BIN_EXE_semon"))
            .args(["analytics", "materialize", "--all", "--proc-root"])
            .arg(fixture.root.join("empty-proc"))
            .args(cli_args(cache.clone()))
            .output()
            .unwrap()
    };
    let run = |args: &[&str]| {
        let output = cli(args, cache.clone());
        let value = serde_json::from_slice::<Value>(&output.stdout).unwrap_or_else(|_| {
            panic!("{args:?}: {}", String::from_utf8_lossy(&output.stderr));
        });
        (output.status.success(), value)
    };
    let (ok, error) = run(&["query", "search", "synthetic"]);
    assert!(!ok);
    assert_eq!(error["error"]["code"], "not_materialized");
    assert!(!cache.parent().unwrap().exists());
    let (ok, error) = run(&["query", "search", "synthetic", "--machine", "/missing"]);
    assert!(!ok);
    assert_eq!(error["error"]["code"], "capability_unavailable");
    assert!(!cache.parent().unwrap().exists());

    let published = materialize();
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
    let (ok, value) = run(&[
        "query",
        "search",
        "\"SEMON_SYNTHETIC_CLAUDE_235\"",
        "--harness",
        "claude",
        "--part",
        "user",
        "--since",
        "2026-10-03T00:00:00Z",
        "--until",
        "2026-10-04T00:00:00Z",
    ]);
    assert!(ok, "{value}");
    let hit = &value["hits"][0];
    assert!(
        hit["snippet"]["untrusted_text"]
            .as_str()
            .unwrap()
            .contains("SEMON_SYNTHETIC_CLAUDE_235")
    );
    let uid = hit["body_uid"].as_str().unwrap();
    assert!(uid.starts_with("origin-"));
    let (ok, body) = run(&["query", "view", uid]);
    assert!(ok, "{body}");
    assert_eq!(
        body["bodies"][0]["text"]["untrusted_text"],
        "SEMON_SYNTHETIC_CLAUDE_235"
    );
    let turn = hit["turn_uid"].as_str().unwrap();
    let (ok, body) = run(&["query", "view", turn, "--part", "user"]);
    assert!(ok, "{body}");
    assert_eq!(body["bodies"][0]["body_uid"], uid);

    let (ok, value) = run(&[
        "query",
        "search",
        "SYNTHETIC_ACK",
        "--harness",
        "codex",
        "--part",
        "assistant",
    ]);
    assert!(ok, "{value}");
    let step = value["hits"][0]["step_uid"].as_str().unwrap();
    let (ok, body) = run(&["query", "view", step]);
    assert!(ok, "{body}");
    assert_eq!(body["bodies"][0]["text"]["untrusted_text"], "SYNTHETIC_ACK");

    let (ok, error) = run(&["query", "search", "\"unterminated"]);
    assert!(!ok);
    assert_eq!(error["error"]["code"], "invalid_query");
    for uid in [
        "label/sample",
        "adjudication/sample",
        "lane/sample",
        "intervention/sample",
        "other/claude/session/t/turn",
    ] {
        let (ok, error) = run(&["query", "view", uid]);
        assert!(!ok);
        assert_eq!(error["error"]["code"], "not_found");
    }

    let mut server = Server::start(cache);
    let reply = server.request(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"query":"SYNTHETIC_ACK","harness":"codex","part":"assistant"}}}));
    let (hits, failed) = content(&reply);
    assert!(!failed, "{hits}");
    assert_eq!(hits["hits"][0]["step_uid"], step);
    let reply = server.request(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"view","arguments":{"uid":step}}}));
    let (body, failed) = content(&reply);
    assert!(!failed, "{body}");
    assert_eq!(body["bodies"][0]["text"]["untrusted_text"], "SYNTHETIC_ACK");
}
