//! urlscan.io-style URL scan report, built from free no-key public APIs.
//!
//! Unlike `links` (fully offline heuristics), this module deliberately makes a
//! handful of outbound HTTPS requests:
//!   - the target URL itself            (page title, status, server, final URL)
//!   - https://dns.google/resolve       (A/AAAA/MX records)
//!   - https://ipwho.is/<ip>            (geolocation, ASN, ISP)
//!   - https://crt.sh/?output=json      (TLS certificate issuances)
//! A screenshot preview is built as a wordpress mshots URL and rendered by the
//! browser; the server never fetches it. Every source failure is recorded in
//! `errors` so one slow or blocked API still yields a partial report.

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use ureq::AgentBuilder;

use crate::links::{self, Verdict};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const CERT_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_PAGE_BYTES: u64 = 256 * 1024;

/// GET a JSON document, flattening ureq's two error types into one string.
fn get_json(agent: &ureq::Agent, url: &str) -> Result<Value, String> {
    let resp = agent.get(url).call().map_err(|e| e.to_string())?;
    resp.into_json::<Value>().map_err(|e| e.to_string())
}

pub struct UrlscanReport {
    pub url: String,
    pub host: String,
    pub page: Value,    // {status, final_url, title, server, content_type, bytes_read}
    pub dns: Value,     // {records: [{type, name, data}]}
    pub ip_info: Value, // {ip, country, country_code, city, asn, org, isp} or null
    pub cert: Value,    // {issuer, common_name, not_before, not_after} or null
    pub screenshot_url: String,
    pub verdict: Verdict,
    pub findings: Vec<links::LinkFinding>,
    pub errors: Vec<String>,
    pub scanned_at: String,
}

pub fn scan_url(raw_url: &str) -> UrlscanReport {
    let mut errors: Vec<String> = Vec::new();
    let url = normalize_url(raw_url);
    let host = host_of(&url);

    let agent = AgentBuilder::new()
        .timeout(HTTP_TIMEOUT)
        .user_agent("hookscan/0.2 (+urlscan; educational)")
        .build();

    // 1. Fetch the page itself (follows redirects; capture metadata + title).
    let mut page = json!({
        "status": Value::Null,
        "final_url": url,
        "title": Value::Null,
        "server": Value::Null,
        "content_type": Value::Null,
        "bytes_read": 0,
    });
    match agent.get(&url).call() {
        Ok(resp) => {
            page["status"] = json!(resp.status());
            page["final_url"] = json!(resp.get_url());
            page["server"] = json!(resp.header("server"));
            page["content_type"] = json!(resp.header("content-type"));
            let mut body = Vec::new();
            let mut limited = resp.into_reader().take(MAX_PAGE_BYTES);
            if let Err(e) = limited.read_to_end(&mut body) {
                errors.push(format!("page body read: {e}"));
            }
            page["bytes_read"] = json!(body.len());
            if let Some(t) = extract_title(&body) {
                page["title"] = json!(t);
            }
        }
        Err(e) => errors.push(format!("page fetch: {e}")),
    }

    // 2. DNS records (dns.google JSON resolver).
    let mut dns = json!({ "records": [] });
    if host.is_empty() {
        errors.push("dns: no host in URL".into());
    } else {
        for rtype in ["A", "AAAA", "MX"] {
            let u = format!("https://dns.google/resolve?name={}&type={}", q(&host), rtype);
            match get_json(&agent, &u) {
                Ok(v) => {
                    if let Some(answers) = v["Answer"].as_array() {
                        for a in answers {
                            let data = a["data"].as_str().unwrap_or_default().to_string();
                            let name = a["name"].as_str().unwrap_or(&host).to_string();
                            let t = match a["type"].as_i64() {
                                Some(1) => "A",
                                Some(28) => "AAAA",
                                Some(15) => "MX",
                                _ => "OTHER",
                            };
                            if t != "OTHER" {
                                dns["records"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(json!({ "type": t, "name": name, "data": data }));
                            }
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("dns {rtype}: {e}"));
                    break; // resolver likely unreachable; skip remaining types
                }
            }
        }
    }

    // 3. IP geolocation / ASN / ISP for the first A record.
    let mut ip_info = json!(Value::Null);
    let a_record = dns["records"]
        .as_array()
        .and_then(|rs| rs.iter().find(|r| r["type"] == "A"))
        .and_then(|r| r["data"].as_str())
        .map(|s| s.to_string());
    if let Some(ip) = a_record {
        let u = format!("https://ipwho.is/{}", q(&ip));
        match get_json(&agent, &u) {
            Ok(v) if v["success"].as_bool().unwrap_or(false) => {
                ip_info = json!({
                    "ip": v["ip"],
                    "country": v["country"],
                    "country_code": v["country_code"],
                    "city": v["city"],
                    "asn": v["connection"]["asn"],
                    "org": v["connection"]["org"],
                    "isp": v["connection"]["isp"],
                });
            }
            Ok(_) => errors.push("ip lookup: ipwho.is reported failure".into()),
            Err(e) => errors.push(format!("ip lookup: {e}")),
        }
    }

    // 4. TLS certificate history (crt.sh). Slow service, so a short timeout and
    //    a tolerated failure.
    let mut cert = json!(Value::Null);
    if let Some(domain) = registrable_domain(&host) {
        let cert_agent = AgentBuilder::new().timeout(CERT_TIMEOUT).build();
        let u = format!("https://crt.sh/?q={}&output=json", q(&domain));
        match get_json(&cert_agent, &u) {
            Ok(v) if v.as_array().map(|a| !a.is_empty()).unwrap_or(false) => {
                let e = &v[0];
                cert = json!({
                    "issuer": e["issuer_name"],
                    "common_name": e["common_name"],
                    "not_before": e["not_before"],
                    "not_after": e["not_after"],
                });
            }
            Ok(_) => {}
            Err(e) => errors.push(format!("cert lookup (crt.sh): {e}")),
        }
    }

    // 5. Verdict from the existing offline heuristics engine.
    let findings = links::analyze(&url);
    let verdict = links::verdict(&findings);

    UrlscanReport {
        screenshot_url: format!(
            "https://s.wordpress.com/mshots/v1/{}?w=1280",
            base64url(url.as_bytes())
        ),
        url,
        host,
        page,
        dns,
        ip_info,
        cert,
        verdict,
        findings,
        errors,
        scanned_at: now_iso8601(),
    }
}

impl UrlscanReport {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&json!({
            "url": self.url,
            "host": self.host,
            "scanned_at": self.scanned_at,
            "verdict": self.verdict.label(),
            "findings": self.findings.iter().map(|f| json!({
                "severity": match f.severity {
                    links::Severity::Info => "info",
                    links::Severity::Low => "low",
                    links::Severity::Medium => "medium",
                    links::Severity::High => "high",
                },
                "rule": f.rule,
                "detail": f.detail,
            })).collect::<Vec<_>>(),
            "page": self.page,
            "dns": self.dns,
            "ip_info": self.ip_info,
            "cert": self.cert,
            "screenshot_url": self.screenshot_url,
            "errors": self.errors,
        }))
        .unwrap_or_else(|_| "{\"error\":\"could not serialize report\"}".into())
    }

    pub fn print_human(&self) {
        println!("{}", self.url);
        println!(
            "  scanned: {}  ·  verdict: {}",
            self.scanned_at,
            self.verdict.label()
        );
        for f in &self.findings {
            let sev = match f.severity {
                links::Severity::Info => "info",
                links::Severity::Low => "low",
                links::Severity::Medium => "medium",
                links::Severity::High => "high",
            };
            println!("  [{sev:6}] {:20} {}", f.rule, f.detail);
        }
        let p = &self.page;
        println!(
            "  page:    status {} · {} bytes · title: {}",
            p["status"].as_u64().map(|s| s.to_string()).unwrap_or_else(|| "n/a".into()),
            p["bytes_read"],
            p["title"].as_str().unwrap_or("(none)")
        );
        if let Some(server) = p["server"].as_str() {
            println!("  server:  {server}");
        }
        println!("  dns:");
        let records = self.dns["records"].as_array().unwrap();
        if records.is_empty() {
            println!("    (no records found)");
        }
        for r in records {
            println!(
                "    {:4} {} -> {}",
                r["type"].as_str().unwrap_or("?"),
                r["name"].as_str().unwrap_or("?"),
                r["data"].as_str().unwrap_or("?")
            );
        }
        if self.ip_info.is_object() {
            let i = &self.ip_info;
            println!(
                "  ip:      {} ({}, {}) · {} · {}",
                i["ip"].as_str().unwrap_or("?"),
                i["city"].as_str().unwrap_or(""),
                i["country"].as_str().unwrap_or(""),
                i["asn"].as_str().unwrap_or(""),
                i["org"].as_str().unwrap_or("")
            );
        }
        if self.cert.is_object() {
            let c = &self.cert;
            println!(
                "  cert:    issued by {} for {} ({} .. {})",
                c["issuer"].as_str().unwrap_or("?"),
                c["common_name"].as_str().unwrap_or("?"),
                c["not_before"].as_str().unwrap_or("?"),
                c["not_after"].as_str().unwrap_or("?"),
            );
        }
        if !self.errors.is_empty() {
            println!("  warnings:");
            for e in &self.errors {
                println!("    - {e}");
            }
        }
        println!("  screenshot: {}", self.screenshot_url);
    }
}

fn normalize_url(raw: &str) -> String {
    let t = raw.trim();
    if t.contains("://") {
        t.to_string()
    } else {
        format!("https://{t}")
    }
}

fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    authority.split(':').next().unwrap_or(authority).to_string()
}

/// Naive eTLD+1: last two labels (no public-suffix list dependency).
fn registrable_domain(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    Some(labels[labels.len() - 2..].join("."))
}

fn extract_title(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_lowercase();
    let start = lower.find("<title")?;
    let after = lower[start..].find('>')? + start + 1;
    let end = lower[after..].find("</title>")? + after;
    let title = text[after..end].split_whitespace().collect::<Vec<_>>().join(" ");
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(200).collect())
    }
}

fn q(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn base64url(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out.trim_end_matches('=').to_string()
}

/// Current UTC time as ISO-8601, no external time crate.
fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days algorithm.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("https://www.google.com/a?b#c"), "www.google.com");
        assert_eq!(host_of("http://user:pw@1.2.3.4:8080/x"), "1.2.3.4");
        assert_eq!(host_of("example.com"), "example.com");
    }

    #[test]
    fn registrable() {
        assert_eq!(registrable_domain("login.paypal.com"), Some("paypal.com".into()));
        assert_eq!(registrable_domain("paypal.com"), Some("paypal.com".into()));
        assert_eq!(registrable_domain("localhost"), None);
    }

    #[test]
    fn title_extraction() {
        let html = b"<html><head><title>  My   Blog </title></head></html>";
        assert_eq!(extract_title(html).as_deref(), Some("My Blog"));
        assert_eq!(extract_title(b"<TITLE>Up</TITLE>"), Some("Up".to_string()));
        assert_eq!(extract_title(b"no title here"), None);
        assert_eq!(extract_title(b"<title></title>"), None);
    }

    #[test]
    fn base64url_matches_rfc4648() {
        assert_eq!(base64url(b"hello world"), "aGVsbG8gd29ybGQ");
        assert_eq!(base64url(b"hi"), "aGk");
        assert_eq!(base64url(b"ab"), "YWI");
        assert!(!base64url(b"a/b+c?d").contains('/'));
    }

    #[test]
    fn iso_timestamp_shape() {
        let t = now_iso8601();
        // Fixed layout YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z'));
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
    }

    #[test]
    fn offline_scan_still_yields_report_when_network_fails() {
        // No network guarantee in tests: scan_url must never panic and must
        // record failed sources in `errors` instead of dying.
        let r = scan_url("notaurl.invalid");
        assert!(r.host.contains("notaurl.invalid"));
        assert!(r.errors.iter().any(|e| e.starts_with("page fetch")));
        let j = r.to_json();
        assert!(j.contains("\"verdict\""));
        assert!(j.contains("\"screenshot_url\""));
    }
}
