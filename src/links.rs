use std::net::IpAddr;

/// One heuristic hit on a URL.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkFinding {
    pub severity: Severity,
    pub rule: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Clean = 0,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
        }
    }
}

/// Read-only, offline URL analysis: static heuristics only, nothing is fetched,
/// no URL is ever sent anywhere.
pub fn analyze(url: &str) -> Vec<LinkFinding> {
    let mut out = Vec::new();
    let lower = url.to_lowercase();

    // --- scheme ---
    let (scheme, rest) = match lower.split_once("://") {
        Some((s, r)) => (s.to_string(), r.to_string()),
        None => {
            out.push(LinkFinding {
                severity: Severity::Low,
                rule: "no-scheme",
                detail: "URL has no scheme; treat http:// as unencrypted".into(),
            });
            (String::new(), lower.clone())
        }
    };
    if scheme == "http" {
        out.push(LinkFinding {
            severity: Severity::Low,
            rule: "http-plain",
            detail: "plain HTTP: content and credentials are unencrypted".into(),
        });
    }

    // --- host ---
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority); // drop userinfo
    let host = authority.split(':').next().unwrap_or(authority);
    let host = host.trim_start_matches('[').trim_end_matches(']');

    // Raw-IP hosts hide the real registrar identity (common in phishing kits).
    if let Ok(ip) = host.parse::<IpAddr>() {
        out.push(LinkFinding {
            severity: Severity::Medium,
            rule: "raw-ip-host",
            detail: format!("host is a raw IP ({ip}) instead of a domain name"),
        });
    }

    // Punycode / homoglyph domains (e.g. xn--pypal-4ve.com).
    if host.contains("xn--") {
        out.push(LinkFinding {
            severity: Severity::Medium,
            rule: "punycode-host",
            detail: "host uses punycode (xn--), possible homoglyph look-alike".into(),
        });
        // Decode punycode labels so brand look-alikes are caught even when the
        // ASCII form (xn--pypal-4ve) no longer contains the brand string.
        let decoded = decode_punycode_host(host);
        let dl = fold_homoglyphs(&decoded.to_lowercase());
        for brand in ["paypal", "apple", "icloud", "microsoft", "amazon", "netflix", "coinbase", "facebook", "whatsapp", "google"] {
            let registrable = dl.split('.').nth(1).unwrap_or("");
            if dl.contains(brand) && fold_homoglyphs(registrable) != brand {
                out.push(LinkFinding {
                    severity: Severity::High,
                    rule: "brand-off-host",
                    detail: format!(
                        "punycode host decodes to '{decoded}', a look-alike of '{brand}'"
                    ),
                });
                break;
            }
        }
    }

    // Credential-bearing URL: password is exposed in the link itself.
    if authority.contains('@') {
        out.push(LinkFinding {
            severity: Severity::Medium,
            rule: "userinfo-in-url",
            detail: "URL embeds a username/password before the host".into(),
        });
    }

    // --- path & query ---
    let path = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
    let path_lower = path.to_lowercase();
    let file = path_lower.rsplit('/').next().unwrap_or("");

    // Executable / installer payloads.
    for ext in [".exe", ".msi", ".scr", ".bat", ".cmd", ".apk", ".dmg", ".deb", ".rpm"] {
        if file.ends_with(ext) {
            out.push(LinkFinding {
                severity: Severity::High,
                rule: "executable-payload",
                detail: format!("path downloads a {ext} executable or installer"),
            });
            break;
        }
    }

    // Scripted-office / macro documents.
    for ext in [".docm", ".xlsm", ".pptm", ".jar", ".hta", ".lnk"] {
        if file.ends_with(ext) {
            out.push(LinkFinding {
                severity: Severity::High,
                rule: "macro-document",
                detail: format!("path downloads a {ext} file, commonly used for macro malware"),
            });
            break;
        }
    }

    // Brand keywords on a foreign host = classic phishing pattern.
    let brands = [
        "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "amazon", "netflix",
        "chase", "wellsfargo", "coinbase", "metamask", "binance", "facebook", "instagram",
        "whatsapp", "dhl", "fedex", "usps",
    ];
    let label = host.rsplit('.').nth(1).unwrap_or(host); // registrable-domain label
    let label_folded = fold_homoglyphs(&label.to_lowercase());
    let host_folded = fold_homoglyphs(&host.to_lowercase());
    let path_folded = fold_homoglyphs(&path_lower);
    for brand in brands {
        let in_host_label = label_folded.contains(brand);
        let in_path = path_folded.contains(brand);
        if in_host_label || (in_path && !host_folded.contains(brand)) {
            let where_ = if in_host_label { "host" } else { "path" };
            out.push(LinkFinding {
                severity: Severity::High,
                rule: "brand-off-host",
                detail: format!(
                    "brand keyword '{brand}' appears in the {where_} but the host is '{host}'"
                ),
            });
            break;
        }
    }

    // Deceptive keywords common in phishing lures.
    for kw in ["verify", "secure", "login", "account", "update", "confirm", "billing"] {
        if host.contains(kw) {
            out.push(LinkFinding {
                severity: Severity::Medium,
                rule: "urgency-keyword-host",
                detail: format!("host contains lure keyword '{kw}'"),
            });
            break;
        }
    }

    // Very long URLs and heavy percent-encoding hide the real destination.
    if url.len() > 120 {
        out.push(LinkFinding {
            severity: Severity::Low,
            rule: "very-long-url",
            detail: format!("URL is {} chars long", url.len()),
        });
    }
    let encoded = url.matches('%').count();
    if encoded >= 8 {
        out.push(LinkFinding {
            severity: Severity::Medium,
            rule: "heavy-encoding",
            detail: format!(
                "URL contains {encoded} percent-escapes, often hiding the destination"
            ),
        });
    }

    out.sort();
    out
}

/// Fold common Cyrillic/Greek homoglyphs to their ASCII look-alikes so brand
/// matching catches IDN attacks like `pаypal.com` (Cyrillic а).
fn fold_homoglyphs(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'а' | 'ɑ' | 'α' => 'a',
            'е' | 'ε' => 'e',
            'о' | 'ο' => 'o',
            'р' | 'ρ' => 'p',
            'с' | 'ϲ' => 'c',
            'х' | 'χ' => 'x',
            'у' | 'γ' => 'y',
            'і' | 'ι' | '𝗂' => 'i',
            'ѕ' => 's',
            'ј' => 'j',
            'κ' | 'к' => 'k',
            'τ' => 't',
            'υ' | 'ν' => 'u',
            'ԁ' | 'ⅾ' => 'd',
            'ո' => 'n',
            'ց' => 'g',
            other => other,
        })
        .collect()
}

pub fn verdict(findings: &[LinkFinding]) -> Verdict {
    match findings.iter().map(|f| f.severity).max() {
        Some(Severity::High) => Verdict::Malicious,
        Some(_) => Verdict::Suspicious,
        None => Verdict::Clean,
    }
}

pub fn to_json(url: &str, findings: &[LinkFinding]) -> String {
    let v = verdict(findings);
    let items: Vec<String> = findings
        .iter()
        .map(|f| {
            format!(
                "    {{\"severity\": \"{}\", \"rule\": \"{}\", \"detail\": \"{}\"}}",
                sev_name(f.severity),
                f.rule,
                escape(&f.detail)
            )
        })
        .collect();
    format!(
        "{{\n  \"url\": \"{}\",\n  \"verdict\": \"{}\",\n  \"findings\": [\n{}\n  ]\n}}",
        escape(url),
        v.label(),
        items.join(",\n")
    )
}

fn sev_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Decode a punycode label (RFC 3492) to Unicode, std-only. Returns the input
/// unchanged if it is not valid punycode.
fn decode_punycode_host(host: &str) -> String {
    let mut out_parts: Vec<String> = Vec::new();
    for label in host.split('.') {
        if let Some(enc) = label.strip_prefix("xn--") {
            out_parts.push(decode_punycode_label(enc).unwrap_or_else(|| label.to_string()));
        } else {
            out_parts.push(label.to_string());
        }
    }
    out_parts.join(".")
}

fn decode_punycode_label(enc: &str) -> Option<String> {
    let (basic_part, encoded) = match enc.rfind('-') {
        Some(pos) => (&enc[..pos], &enc[pos + 1..]),
        None => ("", enc),
    };
    let mut output: Vec<char> = basic_part.chars().collect();
    let base = 36u32;
    let tmin = 1u32;
    let tmax = 26u32;
    let skew = 38u32;
    let damp = 700u32;
    let initial_bias = 72u32;
    let initial_n = 128u32;

    let mut n = initial_n;
    let mut i = 0u32;
    let mut bias = initial_bias;
    let mut chars = encoded.chars().peekable();
    if encoded.is_empty() {
        return Some(output.iter().collect());
    }
    loop {
        let old_i = i;
        let mut digit: u32;
        let mut w = 1u32;
        let mut k = base;
        loop {
            let c = chars.peek().copied()?;
            let d = match c {
                'a'..='z' => c as u32 - 'a' as u32,
                'A'..='Z' => c as u32 - 'A' as u32,
                '0'..='9' => c as u32 - '0' as u32 + 26,
                _ => return None,
            };
            digit = d;
            chars.next();
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                tmin
            } else if k >= bias + tmax {
                tmax
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(base - t)?;
            k += base;
        }
        // chars must be fully consumed by the final iteration
        let out_len = output.len() as u32 + 1;
        bias = adapt(i - old_i, out_len, old_i == 0, damp, skew, tmin, tmax);
        n = n.checked_add(i / out_len)?;
        i %= out_len;
        let ch = char::from_u32(n)?;
        output.insert(i as usize, ch);
        i += 1;
        if chars.peek().is_none() {
            break;
        }
    }
    Some(output.iter().collect())
}

fn adapt(
    mut delta: u32,
    numpoints: u32,
    first: bool,
    damp: u32,
    skew: u32,
    tmin: u32,
    tmax: u32,
) -> u32 {
    const BASE: u32 = 36;
    delta = if first { delta / damp } else { delta / 2 };
    delta += delta / numpoints;
    let mut k = 0;
    while delta > ((BASE - tmin) * tmax) / 2 {
        delta /= BASE - tmin;
        k += BASE;
    }
    k + (((BASE - tmin + 1) * delta) / (delta + skew))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_url_has_no_findings() {
        assert_eq!(analyze("https://rust-lang.org/"), Vec::new());
        assert_eq!(verdict(&analyze("https://rust-lang.org/")), Verdict::Clean);
    }

    #[test]
    fn punycode_and_brand_lookalike() {
        let f = analyze("https://xn--pypal-4ve.com/login");
        assert!(f.iter().any(|x| x.rule == "punycode-host"));
        assert!(f.iter().any(|x| x.rule == "brand-off-host"));
        assert_eq!(verdict(&f), Verdict::Malicious);
    }

    #[test]
    fn executable_payload_is_high() {
        let f = analyze("https://cdn.example.net/downloads/agent.exe");
        assert!(f.iter().any(|x| x.rule == "executable-payload"));
        assert_eq!(verdict(&f), Verdict::Malicious);
    }

    #[test]
    fn plain_http_is_low() {
        let f = analyze("http://example.org/page");
        assert!(f.iter().any(|x| x.rule == "http-plain"));
        assert_eq!(verdict(&f), Verdict::Suspicious);
    }

    #[test]
    fn brand_in_path_only_is_flagged() {
        let f = analyze("https://secure-login-verify.xyz/paypal/confirm");
        assert!(f.iter().any(|x| x.rule == "brand-off-host"));
        assert!(f.iter().any(|x| x.rule == "urgency-keyword-host"));
    }

    #[test]
    fn json_output_is_well_formed() {
        let url = "https://cdn.example.net/a.exe";
        let j = to_json(url, &analyze(url));
        // std-only JSON sanity checks (the crate has no serde dependency)
        assert!(j.starts_with('{') && j.ends_with('}'));
        assert!(j.contains("\"verdict\": \"malicious\""));
        assert!(j.contains("\"rule\": \"executable-payload\""));
        assert!(j.contains("\"url\": \"https://cdn.example.net/a.exe\""));
        // balanced braces/brackets
        let (open, close) = (
            j.matches('{').count(),
            j.matches('}').count(),
        );
        assert_eq!(open, close);
        assert_eq!(j.matches('[').count(), j.matches(']').count());
    }
}



