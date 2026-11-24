use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_hookscan")
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

#[test]
fn cli_reports_findings_with_exit_code_1() {
    let out = Command::new(bin())
        .args([
            "--proc-root",
            &fixture("proc"),
            "--group-file",
            &fixture("etc_group"),
            "--json",
        ])
        .output()
        .expect("run hookscan");
    assert_eq!(out.status.code(), Some(1), "stdout: {}", String::from_utf8_lossy(&out.stdout));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for expected in [
        "\"kind\": \"DeviceOpen\"",
        "\"kind\": \"InputGroupAccess\"",
        "\"kind\": \"XtstMapped\"",
        "\"kind\": \"UinputModuleLoaded\"",
        "\"comm\": \"keylog-sim\"",
        "\"target\": \"/dev/input/event3\"",
        "\"severity\": \"high\"",
    ] {
        assert!(stdout.contains(expected), "missing {expected} in:\n{stdout}");
    }
    // JSON parses.
    let parsed: JsonMin = stdout.parse().unwrap();
    assert_eq!(parsed.findings, 4);
}

#[test]
fn cli_clean_fixture_exits_0() {
    let out = Command::new(bin())
        .args(["--proc-root", &fixture("clean"), "--json"])
        .output()
        .expect("run hookscan");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"findings\": []"), "stdout: {stdout}");
}

#[test]
fn cli_human_output_exits_1() {
    let out = Command::new(bin())
        .args(["--proc-root", &fixture("proc")])
        .output()
        .expect("run hookscan");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("open fd 3 -> /dev/input/event3"), "stdout: {stdout}");
}

#[test]
fn cli_links_json_multi_url_is_a_valid_array() {
    let out = Command::new(bin())
        .args(["links", "--json", "https://example.com/a", "https://example.com/b"])
        .output()
        .expect("run hookscan links --json");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    assert!(trimmed.starts_with('['), "missing leading [: {trimmed}");
    assert!(trimmed.ends_with(']'), "missing trailing ]: {trimmed}");
    // balanced objects: two entries
    assert_eq!(stdout.matches("\"url\":").count(), 2, "stdout: {stdout}");
}

// Minimal stand-in so the JSON assertion does not pull a JSON dependency:
// counts occurrences of "\"kind\":".
#[derive(Debug)]
struct JsonMin {
    findings: usize,
}

impl std::str::FromStr for JsonMin {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.trim_start().starts_with('{') || !s.trim_end().ends_with('}') {
            return Err("not a JSON object".into());
        }
        Ok(JsonMin {
            findings: s.matches("\"kind\":").count(),
        })
    }
}
