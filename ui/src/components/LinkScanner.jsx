import { useState } from 'react'

const VERDICT_TONE = {
  clean: 'sev-low',
  suspicious: 'sev-medium',
  dangerous: 'sev-high',
}

function UrlRow({ result }) {
  const [open, setOpen] = useState(false)
  const tone = VERDICT_TONE[result.verdict] || 'sev-medium'
  const hasFindings = result.findings.length > 0
  return (
    <li className="link-row">
      <div className="link-row-head">
        <span className={`sev-badge sev-badge-sm ${tone}`}>{result.verdict}</span>
        <span className="link-url" title={result.url}>
          {result.url}
        </span>
        {hasFindings && (
          <button className="filter-btn" onClick={() => setOpen(!open)} aria-expanded={open}>
            {open ? 'hide' : `${result.findings.length} finding${result.findings.length > 1 ? 's' : ''}`}
          </button>
        )}
      </div>
      {open && (
        <ul className="link-findings">
          {result.findings.map((f, i) => (
            <li key={i} className={`legend-item sev-${f.severity}`}>
              <span className="sev-badge sev-badge-sm">{f.severity}</span>
              <span>
                <code>{f.rule}</code> — {f.detail}
              </span>
            </li>
          ))}
        </ul>
      )}
    </li>
  )
}

export default function LinkScanner() {
  const [input, setInput] = useState('')
  const [results, setResults] = useState(null)
  const [state, setState] = useState('idle') // 'idle' | 'loading' | 'error'
  const [error, setError] = useState(null)

  async function scan(e) {
    e.preventDefault()
    const urls = input
      .split(/[\s,]+/)
      .map((u) => u.trim())
      .filter(Boolean)
    if (urls.length === 0) return
    setState('loading')
    setError(null)
    try {
      const res = await fetch(`/api/links?urls=${encodeURIComponent(urls.join(' '))}`, {
        headers: { Accept: 'application/json' },
      })
      const body = await res.json().catch(() => null)
      if (!res.ok) throw new Error(body?.error || `scan failed (HTTP ${res.status})`)
      if (!Array.isArray(body?.results)) throw new Error('unexpected link-scan response')
      setResults(body.results)
      setState('idle')
    } catch (err) {
      setError(err.message || 'could not reach the link scanner')
      setState('error')
    }
  }

  return (
    <section id="links" className="report-section" aria-label="Link scanner">
      <div className="section-head">
        <h2>Link scanner</h2>
        <span className="section-meta">offline heuristics · no URL is ever fetched</span>
      </div>
      <form className="link-form" onSubmit={scan}>
        <label className="visually-hidden" htmlFor="link-input">
          URLs to check
        </label>
        <input
          id="link-input"
          className="link-input"
          type="text"
          placeholder="Paste one or more URLs (space or comma separated)…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          spellCheck="false"
          autoComplete="off"
        />
        <button className="btn btn-primary" type="submit" disabled={state === 'loading' || !input.trim()}>
          {state === 'loading' ? 'checking…' : 'Check links'}
        </button>
      </form>

      {state === 'error' && (
        <div className="scan-error" role="alert">
          <strong>Link scan failed:</strong> {error}
        </div>
      )}

      {results && (
        <ul className="link-list">
          {results.map((r) => (
            <UrlRow key={r.url} result={r} />
          ))}
        </ul>
      )}

      {!results && state !== 'loading' && (
        <p className="empty-hint">
          Checks punycode/homoglyph brand look-alikes, IP-address hosts, credential-bait paths like{' '}
          <code>/login</code>, and executable downloads — entirely offline, like the CLI&apos;s{' '}
          <code>hookscan links</code>.
        </p>
      )}
    </section>
  )
}
