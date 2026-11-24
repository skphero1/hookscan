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
    let path = path.split('?').next().unwrap_or(path);

    // Drain the remaining headers so keep-alive clients are not left hanging.
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
    }

    let (status, content_type, body) = route(method, path, ui_dir, proc_root, group_file);
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

fn route(
    method: &str,
    path: &str,
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
}
