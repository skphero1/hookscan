# hookscan

**hookscan** is a read-only Rust scanner that audits which processes on a Linux host can read your keystrokes. It is the defensive side of the keylogger question: instead of capturing input, it shows you what already could.

## What it detects

- **High** — a process holding an open file descriptor to a `/dev/input/event*` or `/dev/uinput` device (this is what a keylogger does).
- **Medium** — a process running in the `input` group, able to open any input device even if it has not yet.
- **Low** — a process with `libXtst` mapped (capable of X11 synthetic-input/XRecord capture) and a loaded `uinput` kernel module.

It is fully read-only: no writes outside its own output, no network connections. Run with `sudo` to inspect every process's file descriptors.

## Build and run

```sh
cargo build --release
sudo ./target/release/hookscan            # text report
sudo ./target/release/hookscan --json     # machine-readable report for CI
cargo test                                # 7 tests, fixture-based
```

## Web UI

`ui/` contains a React + Vite dashboard that renders a scan report the way an audit console would: severity filters, a raw JSON view, loading skeletons and an empty state. Sample data lives in `ui/src/report.fixtures.json`; a real report comes from `sudo hookscan --json`.

```sh
cd ui
npm install
npm run dev      # dev server
npm run build    # production build in ui/dist
```

## Threat-model notes

Detection signals defenders can alert on: unexpected accessibility/input permissions, raw HID device reads, unknown autostart entries, and processes holding input hooks or opening `/dev/input`. Diff `hookscan --json` output over time (cron/systemd timer) to catch new input readers.
