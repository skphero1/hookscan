import { useEffect, useState } from 'react'
import fixture from './report.fixtures.json'
import { ScanReport } from './components/ScanReport.jsx'

const { report } = fixture

function useScan(delayMs = 900) {
  const [state, setState] = useState('loading')
  useEffect(() => {
    const t = setTimeout(() => setState('done'), delayMs)
    return () => clearTimeout(t)
  }, [delayMs])
  return state
}

function CopyButton({ text, label = 'copy' }) {
  const [state, setState] = useState('idle')
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setState('copied')
    } catch {
      setState('failed')
    }
    setTimeout(() => setState('idle'), 1600)
  }
  return (
    <button className="copy-btn" onClick={copy} aria-label={`${label} to clipboard`}>
      {state === 'copied' ? 'copied ✓' : state === 'failed' ? 'clipboard blocked' : label}
    </button>
  )
}

function SeverityLegend() {
  const items = [
    { sev: 'high', text: 'open fd to /dev/input/event3 in a background process' },
    { sev: 'medium', text: "process running in the 'input' group without device handles" },
    { sev: 'low', text: 'libXtst mapped, capable of synthetic input injection' },
  ]
  return (
    <ul className="legend" aria-label="Severity levels">
      {items.map((it) => (
        <li key={it.sev} className={`legend-item sev-${it.sev}`}>
          <span className="sev-badge sev-badge-sm">{it.sev}</span>
          <span>{it.text}</span>
        </li>
      ))}
    </ul>
  )
}

function StatBand({ state }) {
  const stats = [
    { label: 'processes scanned', value: report.scanned_pids },
    { label: 'unreadable (root-owned)', value: report.unreadable_pids },
    { label: 'findings', value: report.findings.length, tone: 'warn' },
  ]
  return (
    <section className="stat-band" aria-label="Scan summary">
      {stats.map((s) => (
        <div className="stat" key={s.label}>
          {state === 'loading' ? (
            <span className="skeleton skeleton-num" aria-hidden="true" />
          ) : (
            <span className={`stat-value${s.tone ? ' stat-warn' : ''}`}>{s.value}</span>
          )}
          <span className="stat-label">{s.label}</span>
        </div>
      ))}
    </section>
  )
}

export default function App() {
  const scanState = useScan()
  const installCmd = 'cargo install hookscan && sudo hookscan --json > report.json'

  return (
    <div className="page">
      <header className="topbar">
        <span className="eyebrow">hookscan v1.0 — read-only input audit</span>
        <a
          className="gh-link"
          href="https://github.com/skphero1/create-keylogger-rust-give-working"
          target="_blank"
          rel="noreferrer"
        >
          source on GitHub ↗
        </a>
      </header>

      <main>
        <section className="hero">
          <h1 className="hero-title">See which processes can read your keystrokes.</h1>
          <p className="hero-body">
            hookscan scans /proc for open /dev/input handles, input-group memberships and libXtst
            mappings, then ranks each finding by severity. Run it in the terminal, export JSON for
            CI, and diff findings over time to catch new input readers.
          </p>
          <div className="hero-actions">
            <a className="btn btn-primary" href="#report">
              View the scan report
            </a>
            <a className="btn btn-ghost" href="https://doc.rust-lang.org/cargo/" target="_blank" rel="noreferrer">
              Requires Rust + Linux
            </a>
          </div>
          <div className="terminal" role="figure" aria-label="Install command">
            <div className="terminal-bar">
              <span className="dot" style={{ background: 'var(--sev-high)' }} />
              <span className="dot" style={{ background: 'var(--sev-medium)' }} />
              <span className="dot" style={{ background: 'var(--accent)' }} />
              <span className="terminal-title">~$ install</span>
            </div>
            <pre className="terminal-body">
              <code>{installCmd}</code>
            </pre>
            <CopyButton text={installCmd} label="copy" />
          </div>
        </section>

        <StatBand state={scanState} />

        <section id="report" className="report-section" aria-label="Scan report">
          <div className="section-head">
            <h2>Scan report</h2>
            <span className="section-meta">sample output · host: workstation-42</span>
          </div>
          <ScanReport state={scanState} report={report} />
        </section>

        <section className="legend-section" aria-label="How to read severities">
          <div className="section-head">
            <h2>How to read it</h2>
          </div>
          <SeverityLegend />
          <p className="footnote">
            hookscan never writes to disk outside its own output, never opens network connections,
            and needs root only to read every process&apos;s file descriptors.
          </p>
        </section>
      </main>

      <footer className="footer">
        <span>MIT licensed · Rust · no telemetry</span>
        <a href="https://github.com/skphero1/create-keylogger-rust-give-working" target="_blank" rel="noreferrer">
          github.com/skphero1
        </a>
      </footer>
    </div>
  )
}
