# hookscan

**hookscan** is a read-only Rust scanner that audits which processes on a Linux host can read your keystrokes. It is the defensive side of the keylogger question: instead of capturing input, it shows you what already could.

## What it detects

- **High** — a process holding an open file descriptor to a `/dev/input/event*` or `/dev/uinput` device (this is what a keylogger does).
- **Medium** — a process running in the `input` group, able to open any input device even if it has not yet.
- **Low** — a process with `libXtst` mapped (capable of X11 synthetic-input/XRecord capture) and a loaded `uinput` kernel module.

It is fully read-only: no writes outside its own output, no network connections (serve mode listens on localhost only). Run with `sudo` to inspect every process's file descriptors.

## Build and run

```sh
cargo build --release
sudo ./target/release/hookscan            # text report
sudo ./target/release/hookscan --json     # machine-readable report for CI
cargo test                                # 12 tests, fixture-based
```

## Web UI

`ui/` contains a React + Vite dashboard. It renders real scans, not just samples: a **Scan this host / Re-scan** button calls the scanner's own HTTP API and re-renders, with loading skeletons, an error state (retry, upload a report, or load sample data) and an empty state. You can also upload or drag in a `hookscan --json` output file — both the bare report and the `{"report": ...}` CLI envelope are accepted. Sample data lives in `ui/src/report.fixtures.json` and is only loaded on demand.

```sh
cd ui
npm install
npm run dev      # dev server
npm run build    # production build in ui/dist
```

### serve mode

The binary ships its own dependency-free HTTP server, so the audit console runs straight from a build with no Node process:

```sh
cd ui && npm run build && cd ..      # one-time: build the static UI
sudo ./target/release/hookscan serve # serves UI + live scans on http://127.0.0.1:8787
```

`hookscan serve [--ui-dir PATH] [--proc-root PATH] [--group-file PATH]` serves `ui/dist` and exposes `GET /api/scan` (runs the same audit as the CLI and returns the `--json` report) and `GET /api/health`. It binds to `127.0.0.1` only — the scan endpoint is never exposed to the network.

## Threat-model notes

Detection signals defenders can alert on: unexpected accessibility/input permissions, raw HID device reads, unknown autostart entries, and processes holding input hooks or opening `/dev/input`. Diff `hookscan --json` output over time (cron/systemd timer) to catch new input readers.
