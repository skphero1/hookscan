import { useCallback, useState } from 'react'
import fixture from './report.fixtures.json'
import { ScanReport } from './components/ScanReport.jsx'
import LinkScanner from './components/LinkScanner.jsx'

const SAMPLE = fixture.report

// Handles both live serve output ({...report}) and saved CLI files ({"report": {...}}).
function unwrapReport(data) {
  if (!data || typeof data !== 'object') return null
  const r = data.report && typeof data.report === 'object' ? data.report : data
  const findings = Array.isArray(r.findings) ? r.findings : null
  if (findings === null || typeof r.scanned_pids !== 'number') return null
  return { ...r, findings }
}

async function fetchScan() {
  const res = await fetch('/api/scan', { headers: { Accept: 'application/json' } })
  const body = await res.json().catch(() => null)
  if (!res.ok) {
    throw new Error(body?.error || `scan failed (HTTP ${res.status})`)
  }
  const report = unwrapReport(body)
  if (!report) throw new Error('scan response was not a hookscan report')
  return report
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

function StatBand({ state, report }) {
  const stats = [
    { label: 'processes scanned', value: report?.scanned_pids },
    { label: 'unreadable (root-owned)', value: report?.unreadable_pids },
    { label: 'findings', value: report?.findings?.length ?? 0, tone: 'warn' },
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

function ReportMeta({ report, source }) {
  if (!report) return null
  const scannedAt = report.scanned_at
  return (
    <span className="section-meta">
      {source === 'file' ? 'loaded from file' : source === 'live' ? 'live scan' : 'loaded report'}
      {scannedAt ? ` · ${scannedAt}` : ''}
    </span>
  )
}

export default function App() {
  const [report, setReport] = useState(null)
  const [source, setSource] = useState('none') // 'live' | 'file' | 'sample' | 'none'
  const [state, setState] = useState('idle') // 'idle' | 'loading' | 'error'
  const [error, setError] = useState(null)

  const rescan = useCallback(async () => {
    setState('loading')
    setError(null)
    try {
      const r = await fetchScan()
      setReport(r)
      setSource('live')
      setState('idle')
    } catch (e) {
      setError(e.message || 'could not reach the scanner')
      setState('error')
    }
  }, [])

  function loadFile(file) {
    const reader = new FileReader()
    reader.onload = () => {
      try {
        const r = unwrapReport(JSON.parse(reader.result))
        if (!r) throw new Error('not a hookscan report (expected scanned_pids and findings)')
        setReport(r)
        setSource('file')
        setState('idle')
        setError(null)
      } catch (e) {
        setError(e.message)
        setState('error')
      }
    }
    reader.readAsText(file)
  }

  const installCmd = 'hookscan serve  # serves the UI + live /api/scan on http://127.0.0.1:8787'

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
            <button className="btn btn-primary" onClick={rescan} disabled={state === 'loading'}>
              {state === 'loading' ? 'scanning…' : report ? 'Re-scan' : 'Scan this host'}
            </button>
            <label className="btn btn-ghost" htmlFor="report-upload">
              Upload report
            </label>
            <input
              id="report-upload"
              type="file"
              accept=".json,application/json"
              style={{ display: 'none' }}
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) loadFile(f)
                e.target.value = ''
              }}
            />
          </div>
          <div className="terminal" role="figure" aria-label="Install command">
            <div className="terminal-bar">
              <span className="dot" style={{ background: 'var(--sev-high)' }} />
              <span className="dot" style={{ background: 'var(--sev-medium)' }} />
              <span className="dot" style={{ background: 'var(--accent)' }} />
              <span className="terminal-title">~$ run</span>
            </div>
            <pre className="terminal-body">
              <code>{installCmd}</code>
            </pre>
            <CopyButton text={installCmd} label="copy" />
          </div>
        </section>

        <StatBand state={state} report={report} />

        {state === 'error' && (
          <div className="scan-error" role="alert">
            <strong>Scan failed:</strong> {error}
            <div className="scan-error-actions">
              <button className="filter-btn" onClick={rescan}>
                try again
              </button>
              <label className="filter-btn" htmlFor="report-upload-error">
                upload a report.json
              </label>
              <input
                id="report-upload-error"
                type="file"
                accept=".json,application/json"
                style={{ display: 'none' }}
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  if (f) loadFile(f)
                  e.target.value = ''
                }}
              />
              <button
                className="filter-btn"
                onClick={() => {
                  setReport(SAMPLE)
                  setSource('sample')
                  setState('idle')
                  setError(null)
                }}
              >
                load sample data
              </button>
            </div>
          </div>
        )}

        {state === 'idle' && !report && (
          <div className="empty" role="status">
            <p>No report loaded yet.</p>
            <p className="empty-hint">
              Run <code>Scan this host</code> against <code>hookscan serve</code>, or upload a{' '}
              <code>hookscan --json</code> output file.
            </p>
          </div>
        )}

        {report && state !== 'loading' && (
          <section id="report" className="report-section" aria-label="Scan report">
            <div className="section-head">
              <h2>Scan report</h2>
              <ReportMeta report={report} source={source} />
            </div>
            <ScanReport state={state} report={report} />
          </section>
        )}

        <LinkScanner />

        <section className="legend-section" aria-label="How to read severities">          <div className="section-head">
            <h2>How to read it</h2>
          </div>
          <SeverityLegend />
          <p className="footnote">
            hookscan never writes to disk outside its own output, never opens network connections,
            and needs root only to read every process&apos;s file descriptors. <code>serve</code>{' '}
            listens on 127.0.0.1 only — it never exposes the scan to the network.
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
