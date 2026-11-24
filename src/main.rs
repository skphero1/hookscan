mod links;
mod scan;
mod serve;
mod urlscan;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::scan::{resolve_input_gid, scan, to_json};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("serve") => serve_command(args.into_iter().skip(1).collect()),
        Some("links") => links_command(args.into_iter().skip(1).collect()),
        Some("urlscan") => urlscan_command(args.into_iter().skip(1).collect()),
        _ => scan_command(args),
    }
}

fn links_command(args: Vec<String>) -> ExitCode {
    let mut json = false;
    let mut urls: Vec<String> = Vec::new();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" => json = true,
            "-" => {
                use std::io::BufRead;
                for line in std::io::stdin().lock().lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("error: cannot read stdin: {e}");
                            return ExitCode::from(2);
                        }
                    };
                    let u = line.trim();
                    if !u.is_empty() && !urls.contains(&u.to_string()) {
                        urls.push(u.to_string());
                    }
                }
            }
            other if other.starts_with('-') && other != "-" => {
                eprintln!("error: unknown argument: {other}");
                print_help();
                return ExitCode::from(2);
            }
            other => {
                if !urls.contains(&other.to_string()) {
                    urls.push(other.to_string());
                }
            }
        }
    }
    if urls.is_empty() {
        eprintln!("error: no URLs given — pass them as arguments or via stdin with '-'");
        return ExitCode::from(2);
    }

    let mut suspicious = false;
    if json && urls.len() > 1 {
        println!("[");
    }
    for (i, url) in urls.iter().enumerate() {
        let findings = links::analyze(url);
        let v = links::verdict(&findings);
        if json {
            if i > 0 {
                println!(",");
            }
            println!("{}", links::to_json(url, &findings));
        } else {
            if i > 0 {
                println!();
            }
            println!("{url}");
            if findings.is_empty() {
                println!("  verdict: clean — no heuristic matches");
            } else {
                for f in &findings {
                    let sev = match f.severity {
                        links::Severity::Info => "info",
                        links::Severity::Low => "low",
                        links::Severity::Medium => "medium",
                        links::Severity::High => "high",
                    };
                    println!("  [{sev:6}] {:20} {}", f.rule, f.detail);
                }
                println!("  verdict: {}", v.label());
            }
        }
        if v != links::Verdict::Clean {
            suspicious = true;
        }
    }
    if json && urls.len() > 1 {
        println!("]");
    }
    if suspicious {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn urlscan_command(args: Vec<String>) -> ExitCode {
    let mut json = false;
    let mut urls: Vec<String> = Vec::new();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" => json = true,
            other if other.starts_with('-') => {
                eprintln!("error: unknown argument: {other}");
                print_help();
                return ExitCode::from(2);
            }
            other => urls.push(other.to_string()),
        }
    }
    if urls.is_empty() {
        eprintln!("error: no URL given — e.g. hookscan urlscan https://example.com");
        return ExitCode::from(2);
    }

    for (i, url) in urls.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let report = urlscan::scan_url(url);
        if json {
            println!("{}", report.to_json());
        } else {
            report.print_human();
        }
    }
    ExitCode::SUCCESS
}

fn serve_command(args: Vec<String>) -> ExitCode {
    let mut proc_root = PathBuf::from("/proc");
    let mut group_file = PathBuf::from("/etc/group");
    let mut ui_dir = PathBuf::from("ui/dist");
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--proc-root" => match it.next() {
                Some(v) => proc_root = PathBuf::from(v),
                None => {
                    eprintln!("error: --proc-root needs a path");
                    return ExitCode::from(2);
                }
            },
            "--group-file" => match it.next() {
                Some(v) => group_file = PathBuf::from(v),
                None => {
                    eprintln!("error: --group-file needs a path");
                    return ExitCode::from(2);
                }
            },
            "--ui-dir" => match it.next() {
                Some(v) => ui_dir = PathBuf::from(v),
                None => {
                    eprintln!("error: --ui-dir needs a path");
                    return ExitCode::from(2);
                }
            },
            other => {
                eprintln!("error: unknown argument: {other}");
                print_help();
                return ExitCode::from(2);
            }
        }
    }
    if !ui_dir.is_dir() {
        eprintln!(
            "error: ui dir not found: {} — build it with `cd ui && npm run build`, or pass --ui-dir",
            ui_dir.display()
        );
        return ExitCode::from(2);
    }
    match serve::serve(ui_dir, proc_root, group_file) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn scan_command(args: Vec<String>) -> ExitCode {
    let mut json = false;
    let mut proc_root = PathBuf::from("/proc");
    let mut group_file = PathBuf::from("/etc/group");
    let mut unknown: Vec<String> = Vec::new();

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--proc-root" => match args.next() {
                Some(v) => proc_root = std::path::PathBuf::from(v),
                None => {
                    eprintln!("error: --proc-root needs a path");
                    return ExitCode::from(2);
                }
            },
            "--group-file" => match args.next() {
                Some(v) => group_file = std::path::PathBuf::from(v),
                None => {
                    eprintln!("error: --group-file needs a path");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other => unknown.push(other.to_string()),
        }
    }
    if !unknown.is_empty() {
        eprintln!("error: unknown argument: {}", unknown[0]);
        print_help();
        return ExitCode::from(2);
    }

    let input_gid = resolve_input_gid(&group_file);
    let report = match scan(&proc_root, input_gid) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot read proc root {}: {e}", proc_root.display());
            return ExitCode::from(2);
        }
    };

    if json {
        println!("{}", to_json(&report, &proc_root));
    } else {
        print_human(&report, &proc_root);
    }
    if report.findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn print_human(report: &scan::ScanReport, proc_root: &Path) {
    println!("hookscan — input-hook audit (proc root: {})", proc_root.display());
    if report.devices.is_empty() {
        println!("input devices: none found");
    } else {
        println!("input devices ({}):", report.devices.len());
        for d in &report.devices {
            println!("  - {d}");
        }
    }
    println!(
        "processes scanned: {} ({} unreadable)",
        report.scanned_pids, report.unreadable_pids
    );
    if report.findings.is_empty() {
        println!(
            "result: clean — no /dev/input or /dev/uinput open, no input-group access, no libXtst mapping, no uinput module"
        );
        return;
    }
    println!("findings ({}):", report.findings.len());
    for f in &report.findings {
        println!("  {}", f.render());
    }
    println!(
        "result: {} finding(s) — processes with input-capture capability present",
        report.findings.len()
    );
}

fn print_help() {
    println!("hookscan — audit processes with keyboard/input capture capability on Linux");
    println!();
    println!("USAGE:");
    println!("  hookscan [--json] [--proc-root PATH] [--group-file PATH]");
    println!("  hookscan serve [--ui-dir PATH] [--proc-root PATH] [--group-file PATH]");
    println!("  hookscan links [--json] URL... | -        (stdin: one URL per line)");
    println!("  hookscan urlscan [--json] URL...          urlscan.io-style report (online)");
    println!();
    println!("urlscan mode makes outbound requests: it fetches the page itself and queries");
    println!("dns.google, ipwho.is and crt.sh for DNS, geolocation/ASN and TLS certificates.");
    println!("The screenshot preview is a wordpress mshots URL rendered by your browser.");
    println!();
    println!("links mode: offline heuristic URL analysis. Nothing is fetched, no URL leaves the machine.");
    println!("  checks: raw-IP host, punycode look-alike, embedded credentials, executable/macro");
    println!("  payloads, brand keywords on a foreign host, lure keywords, length, heavy encoding.");
    println!();
    println!("serve mode: serves the UI from ui/dist on http://127.0.0.1:8787 (localhost only).");
    println!("  GET /api/scan   runs the same audit as the CLI and returns the --json report");
    println!("  GET /api/urlscan?url=... urlscan.io-style report (makes outbound requests)");
    println!("  GET /api/health returns {{\"ok\": true}}");
    println!();
    println!("Checks (all read-only, under /proc):");
    println!("  - processes with /dev/input/* or /dev/uinput file descriptors open  [high]");
    println!("  - processes whose effective/supplementary groups include 'input'    [medium]");
    println!("  - processes with libXtst (X11 XRecord) mapped                       [low]");
    println!("  - uinput kernel module loaded                                       [low]");
    println!();
    println!("Exit codes: 0 clean, 1 findings, 2 error. Run as root to see all processes' fds.");
}
