use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

use crate::scan::{resolve_input_gid, scan, to_json};

pub fn serve(ui_dir: PathBuf, proc_root: PathBuf, group_file: PathBuf) -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8787")?;
    eprintln!("hookscan serve: listening on http://127.0.0.1:8787 (local only)");
    eprintln!("  ui dir: {}", ui_dir.display());
    eprintln!("  proc root: {}", proc_root.display());

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("hookscan serve: connection error: {e}");
                continue;
            }
        };
        let ui_dir = ui_dir.clone();
        let proc_root = proc_root.clone();
        let group_file = group_file.clone();
        thread::spawn(move || {
            let _ = handle(stream, &ui_dir, &proc_root, &group_file);
        });
    }
    Ok(())
}

fn handle(
    mut stream: TcpStream,
    ui_dir: &Path,
    proc_root: &Path,
    group_file: &Path,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let raw_query = path.split_once('?').map(|(_, q)| q.to_string()).unwrap_or_default();
    let path = path.split('?').next().unwrap_or(path);

    // Drain the remaining headers so keep-alive clients are not left hanging.
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
    }

    let (status, content_type, body) = route_with_query(
        method,
        path,
        &raw_query,
        ui_dir,
        proc_root,
        group_file,
    );
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    stream.write_all(
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    stream.write_all(&body)?;
    Ok(())
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 && i + 2 < bytes.len() + 1 {
            let hex = bytes.get(i + 1..i + 3).and_then(|h| {
                std::str::from_utf8(h).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
            });
            if let Some(b) = hex {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// GET /api/links?urls=<url>[&urls=<url>...] — offline heuristic scan of the
/// given URLs. Nothing is fetched; only the URLs supplied by the caller are
/// analyzed and no request leaves this machine.
fn links_report(raw_query: &str) -> Result<String, String> {
    let mut urls = Vec::new();
    for pair in raw_query.split('&') {
        if let Some(v) = pair.strip_prefix("urls=") {
            let decoded = percent_decode(v);
            // accept both repeated urls= params and one space/comma-separated value
            for url in decoded.split(|c: char| c.is_whitespace() || c == ',') {
                let url = url.trim();
                if !url.is_empty() {
                    urls.push(url.to_string());
                }
            }
        }
    }
    if urls.is_empty() {
        return Err("missing urls parameter".into());
    }
    if urls.len() > 32 {
        return Err("too many urls (max 32)".into());
    }
    let mut parts = Vec::with_capacity(urls.len());
    for url in &urls {
        let findings = crate::links::analyze(url);
        let findings_json = findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"severity\": \"{}\", \"rule\": \"{}\", \"detail\": {}}}",
                    match f.severity {
                        crate::links::Severity::Info => "info",
                        crate::links::Severity::Low => "low",
                        crate::links::Severity::Medium => "medium",
                        crate::links::Severity::High => "high",
                    },
                    f.rule,
                    json_str(&f.detail),
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!(
            "{{\"url\": {}, \"verdict\": \"{}\", \"findings\": [{}]}}",
            json_str(url),
            crate::links::verdict(&findings).label(),
            findings_json,
        ));
    }
    Ok(format!("{{\"results\": [{}]}}", parts.join(", ")))
}

/// Minimal JSON string escaping.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn route_with_query(
    method: &str,
    path: &str,
    raw_query: &str,
    ui_dir: &Path,
    proc_root: &Path,
    group_file: &Path,
) -> (u16, &'static str, Vec<u8>) {
    match (method, path) {
        ("GET", "/api/health") => (200, "application/json", b"{\"ok\": true}".to_vec()),
        ("GET", "/api/scan") => {
            let input_gid = resolve_input_gid(group_file);
            match scan(proc_root, input_gid) {
                Ok(report) => (
                    200,
                    "application/json",
                    to_json(&report, proc_root).into_bytes(),
                ),
                Err(e) => (
                    500,
                    "application/json",
                    format!("{{\"error\": \"scan failed: {e}\"}}").into_bytes(),
                ),
            }
        }
        ("GET", "/api/links") => match links_report(raw_query) {
            Ok(json) => (200, "application/json", json.into_bytes()),
            Err(e) => (
                400,
                "application/json",
                format!("{{\"error\": \"{e}\"}}").into_bytes(),
            ),
        },
        ("GET", p) if p.starts_with("/api/") => (
            404,
            "application/json",
            b"{\"error\": \"not found\"}".to_vec(),
        ),
        ("GET", p) => match static_file(ui_dir, p) {
            Some((ct, body)) => (200, ct, body),
            None => (
                404,
                "text/plain; charset=utf-8",
                b"404 not found".to_vec(),
            ),
        },
        _ => (
            405,
            "application/json",
            b"{\"error\": \"method not allowed\"}".to_vec(),
        ),
    }
}

fn static_file(ui_dir: &Path, path: &str) -> Option<(&'static str, Vec<u8>)> {
    let rel = path.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    // The UI is a single-page app: unknown paths fall back to index.html.
    let file = ui_dir.join(rel);
    if file.extension().is_some() && !file.exists() {
        // Asset-looking path that does not exist: do not serve index.html for it.
        return None;
    }
    let resolved = if file.exists() {
        file
    } else {
        ui_dir.join("index.html")
    };
    let canonical_dir = std::fs::canonicalize(ui_dir).ok()?;
    let resolved = std::fs::canonicalize(&resolved).ok()?;
    if !resolved.starts_with(&canonical_dir) {
        return None;
    }
    let body = std::fs::read(&resolved).ok()?;
    let ct = match resolved.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    Some((ct, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(path: &str) -> PathBuf {
        PathBuf::from(path)
    }

    fn route(method: &str, path: &str, ui_dir: &Path, proc_root: &Path, group_file: &Path) -> (u16, &'static str, Vec<u8>) {
        route_with_query(method, path, "", ui_dir, proc_root, group_file)
    }

    #[test]
    fn health_route() {
        let (status, ct, body) = route("GET", "/api/health", &p("ui/dist"), &p("/proc"), &p("/etc/group"));
        assert_eq!((status, ct), (200, "application/json"));
        assert_eq!(body, b"{\"ok\": true}");
    }

    #[test]
    fn unknown_api_route_is_404() {
        let (status, _, _) = route("GET", "/api/nope", &p("ui/dist"), &p("/proc"), &p("/etc/group"));
        assert_eq!(status, 404);
    }

    #[test]
    fn post_is_405() {
        let (status, _, _) = route("POST", "/api/scan", &p("ui/dist"), &p("/proc"), &p("/etc/group"));
        assert_eq!(status, 405);
    }

    #[test]
    fn scan_route_runs_the_scanner() {
        let proc_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc");
        let (status, ct, body) =
            route("GET", "/api/scan", &p("ui/dist"), &proc_root, &p("tests/fixtures/etc_group"));
        assert_eq!((status, ct), (200, "application/json"));
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("\"scanned_pids\""));
        assert!(text.contains("DeviceOpen"));
        assert!(text.contains("keylog-sim"));
    }

    #[test]
    fn scan_route_reports_scan_failure() {
        // A proc root we cannot read (missing) makes scan() fail; route maps it to 500.
        let (status, _, _) = route(
            "GET",
            "/api/scan",
            &p("ui/dist"),
            &p("/nonexistent-proc-root-for-test"),
            &p("tests/fixtures/etc_group"),
        );
        assert_eq!(status, 500);
    }

    #[test]
    fn links_route_flags_phishing_url() {
        let (status, ct, body) = route_with_query(
            "GET",
            "/api/links",
            "urls=https%3A%2F%2Fxn--pypal-4ve.com%2Flogin",
            &p("ui/dist"),
            &p("/proc"),
            &p("/etc/group"),
        );
        assert_eq!((status, ct), (200, "application/json"));
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("\"punycode-host\""));
        assert!(text.contains("\"brand-off-host\""));
        assert!(text.contains("\"high\""));
    }

    #[test]
    fn links_route_clean_url() {
        let (status, _, body) = route_with_query(
            "GET",
            "/api/links",
            "urls=https://rust-lang.org/",
            &p("ui/dist"),
            &p("/proc"),
            &p("/etc/group"),
        );
        assert_eq!(status, 200);
        assert!(String::from_utf8(body).unwrap().contains("\"clean\""));
    }

    #[test]
    fn links_route_requires_urls() {
        let (status, _, body) = route_with_query(
            "GET",
            "/api/links",
            "",
            &p("ui/dist"),
            &p("/proc"),
            &p("/etc/group"),
        );
        assert_eq!(status, 400);
        assert!(String::from_utf8(body).unwrap().contains("missing urls"));
    }
}
