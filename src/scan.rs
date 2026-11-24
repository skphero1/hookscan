use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    #[allow(dead_code)]
    Info = 0,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    DeviceOpen {
        pid: u32,
        comm: String,
        fd: String,
        target: String,
        severity: Severity,
    },
    InputGroupAccess {
        pid: u32,
        comm: String,
        gid: u32,
        severity: Severity,
    },
    XtstMapped {
        pid: u32,
        comm: String,
        severity: Severity,
    },
    UinputModuleLoaded {
        severity: Severity,
    },
}

impl Finding {
    pub fn severity(&self) -> Severity {
        match self {
            Finding::DeviceOpen { severity, .. }
            | Finding::InputGroupAccess { severity, .. }
            | Finding::XtstMapped { severity, .. }
            | Finding::UinputModuleLoaded { severity } => *severity,
        }
    }

    pub fn pid(&self) -> Option<u32> {
        match self {
            Finding::DeviceOpen { pid, .. }
            | Finding::InputGroupAccess { pid, .. }
            | Finding::XtstMapped { pid, .. } => Some(*pid),
            Finding::UinputModuleLoaded { .. } => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Finding::DeviceOpen { .. } => "DeviceOpen",
            Finding::InputGroupAccess { .. } => "InputGroupAccess",
            Finding::XtstMapped { .. } => "XtstMapped",
            Finding::UinputModuleLoaded { .. } => "UinputModuleLoaded",
        }
    }

    pub fn render(&self) -> String {
        match self {
            Finding::DeviceOpen {
                pid,
                comm,
                fd,
                target,
                severity,
            } => format!(
                "[{}] pid {pid} ({comm}): open fd {fd} -> {target}",
                severity.as_str()
            ),
            Finding::InputGroupAccess {
                pid,
                comm,
                gid,
                severity,
            } => format!(
                "[{}] pid {pid} ({comm}): in group 'input' (gid {gid}) — can open any /dev/input device",
                severity.as_str()
            ),
            Finding::XtstMapped { pid, comm, severity } => format!(
                "[{}] pid {pid} ({comm}): libXtst mapped — capable of X11 XRecord keystroke capture",
                severity.as_str()
            ),
            Finding::UinputModuleLoaded { severity } => format!(
                "[{}] uinput kernel module loaded — something can inject synthetic input events",
                severity.as_str()
            ),
        }
    }
}

#[derive(Debug, Default)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub unreadable_pids: usize,
    pub scanned_pids: usize,
    pub devices: Vec<String>,
}

pub fn scan(proc_root: &Path, input_gid: Option<u32>) -> io::Result<ScanReport> {
    let mut report = ScanReport {
        devices: list_input_devices(proc_root),
        ..ScanReport::default()
    };

    if let Ok(modules) = fs::read_to_string(proc_root.join("modules")) {
        if modules
            .lines()
            .any(|l| l.starts_with("uinput ") && !l.contains(" 0 $"))
        {
            report.findings.push(Finding::UinputModuleLoaded {
                severity: Severity::Low,
            });
        }
    }

    for entry in fs::read_dir(proc_root)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        report.scanned_pids += 1;
        match scan_pid(&entry.path(), pid, input_gid) {
            Ok(mut found) => report.findings.append(&mut found),
            Err(_) => report.unreadable_pids += 1,
        }
    }

    report.findings.sort_by(|a, b| {
        b.severity()
            .cmp(&a.severity())
            .then_with(|| a.pid().unwrap_or(u32::MAX).cmp(&b.pid().unwrap_or(u32::MAX)))
            .then_with(|| a.kind().cmp(b.kind()))
    });
    Ok(report)
}

fn scan_pid(dir: &Path, pid: u32, input_gid: Option<u32>) -> io::Result<Vec<Finding>> {
    let comm = fs::read_to_string(dir.join("comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| format!("pid:{pid}"));

    let mut findings = Vec::new();

    // Open file descriptors pointing at input devices.
    match fs::read_dir(dir.join("fd")) {
        Ok(fds) => {
            let mut seen_targets: BTreeSet<String> = BTreeSet::new();
            for fd in fds.flatten() {
                let target = match fs::read_link(fd.path()) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if is_input_target(&target) {
                    let s = target.to_string_lossy().to_string();
                    if seen_targets.insert(s.clone()) {
                        findings.push(Finding::DeviceOpen {
                            pid,
                            comm: comm.clone(),
                            fd: fd.file_name().to_string_lossy().to_string(),
                            target: s,
                            severity: Severity::High,
                        });
                    }
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(e),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    // Group membership: 'input' group grants read access to every event device.
    if let Some(gid) = input_gid {
        if let Ok(status) = fs::read_to_string(dir.join("status")) {
            let (eff, groups) = status_gids(&status);
            if eff == Some(gid) || groups.contains(&gid) {
                findings.push(Finding::InputGroupAccess {
                    pid,
                    comm: comm.clone(),
                    gid,
                    severity: Severity::Medium,
                });
            }
        }
    }

    // libXtst mapped => possible X11 XRecord global keystroke capture.
    match fs::read_to_string(dir.join("maps")) {
        Ok(maps) => {
            if maps.lines().any(|l| l.contains("libXtst")) {
                findings.push(Finding::XtstMapped {
                    pid,
                    comm: comm.clone(),
                    severity: Severity::Low,
                });
            }
        }
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(e),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    Ok(findings)
}

fn is_input_target(target: &Path) -> bool {
    let s = target.to_string_lossy();
    s == "/dev/uinput" || s.starts_with("/dev/input/")
}

fn status_gids(status: &str) -> (Option<u32>, Vec<u32>) {
    let mut eff = None;
    let mut groups = Vec::new();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Gid:") {
            let nums: Vec<&str> = rest.split_whitespace().collect();
            if nums.len() > 1 {
                eff = nums[1].parse().ok();
            }
        } else if let Some(rest) = line.strip_prefix("Groups:") {
            groups = rest.split_whitespace().filter_map(|t| t.parse().ok()).collect();
        }
    }
    (eff, groups)
}

fn list_input_devices(proc_root: &Path) -> Vec<String> {
    let mut devices = Vec::new();
    if let Ok(text) = fs::read_to_string(proc_root.join("bus/input/devices")) {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("N: Name=") {
                devices.push(rest.trim_matches('"').to_string());
            }
        }
    }
    devices
}

pub fn resolve_input_gid(group_file: &Path) -> Option<u32> {
    let text = fs::read_to_string(group_file).ok()?;
    for line in text.lines() {
        let mut parts = line.split(':');
        let name = parts.next()?;
        if name == "input" {
            let _ = parts.next()?;
            return parts.next()?.parse().ok();
        }
    }
    None
}

pub fn to_json(report: &ScanReport, proc_root: &Path) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!(
        "  \"proc_root\": \"{}\",\n",
        json_escape(&proc_root.to_string_lossy())
    ));
    out.push_str(&format!(
        "  \"scanned_pids\": {},\n  \"unreadable_pids\": {},\n",
        report.scanned_pids, report.unreadable_pids
    ));
    out.push_str("  \"devices\": [");
    out.push_str(
        &report
            .devices
            .iter()
            .map(|d| format!("\"{}\"", json_escape(d)))
            .collect::<Vec<_>>()
            .join(", "),
    );
    out.push_str("],\n  \"findings\": [");
    if report.findings.is_empty() {
        out.push_str("]\n}");
        return out;
    }
    out.push('\n');
    for f in &report.findings {
        out.push_str("    ");
        out.push_str(&finding_json(f));
        out.push_str(",\n");
    }
    // Replace trailing comma of last element.
    let trimmed = out.trim_end_matches(",\n").to_string();
    out = trimmed;
    out.push_str("\n  ]\n}\n");
    out
}

fn finding_json(f: &Finding) -> String {
    match f {
        Finding::DeviceOpen {
            pid,
            comm,
            fd,
            target,
            severity,
        } => format!(
            "{{\"kind\": \"DeviceOpen\", \"pid\": {pid}, \"comm\": \"{}\", \"fd\": \"{}\", \"target\": \"{}\", \"severity\": \"{}\"}}",
            json_escape(comm),
            json_escape(fd),
            json_escape(target),
            severity.as_str()
        ),
        Finding::InputGroupAccess {
            pid,
            comm,
            gid,
            severity,
        } => format!(
            "{{\"kind\": \"InputGroupAccess\", \"pid\": {pid}, \"comm\": \"{}\", \"gid\": {gid}, \"severity\": \"{}\"}}",
            json_escape(comm),
            severity.as_str()
        ),
        Finding::XtstMapped { pid, comm, severity } => format!(
            "{{\"kind\": \"XtstMapped\", \"pid\": {pid}, \"comm\": \"{}\", \"severity\": \"{}\"}}",
            json_escape(comm),
            severity.as_str()
        ),
        Finding::UinputModuleLoaded { severity } => format!(
            "{{\"kind\": \"UinputModuleLoaded\", \"severity\": \"{}\"}}",
            severity.as_str()
        ),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn detects_findings_in_fixture() {
        let report = scan(&fixture("proc"), Some(13)).expect("scan");
        let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind()).collect();
        assert_eq!(kinds, vec!["DeviceOpen", "InputGroupAccess", "XtstMapped", "UinputModuleLoaded"]);
        match &report.findings[0] {
            Finding::DeviceOpen { pid, comm, fd, target, .. } => {
                assert_eq!((*pid, comm.as_str(), fd.as_str(), target.as_str()),
                    (100, "keylog-sim", "3", "/dev/input/event3"));
            }
            other => panic!("expected DeviceOpen, got {other:?}"),
        }
        assert!(report.devices.iter().any(|d| d.contains("keyboard")));
    }

    #[test]
    fn clean_fixture_has_no_findings() {
        let report = scan(&fixture("clean"), Some(13)).expect("scan");
        assert!(report.findings.is_empty(), "unexpected: {:?}", report.findings);
        assert_eq!(report.scanned_pids, 1);
    }

    #[test]
    fn resolves_input_gid() {
        let f = fixture("etc_group");
        assert_eq!(resolve_input_gid(&f), Some(13));
    }

    #[test]
    fn json_escapes_specials() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
