import { useState } from 'react'

const VERDICT_TONE = {
  clean: 'sev-low',
  suspicious: 'sev-medium',
  malicious: 'sev-high',
}

function VerdictBadge({ verdict }) {
  return (
    <span className={`sev-badge ${VERDICT_TONE[verdict] || 'sev-low'}`}>{verdict}</span>
  )
}

function DnsTable({ records }) {
  if (!records?.length) return <p className="uscan-empty">No DNS records resolved.</p>
  return (
    <table className="uscan-table">
      <thead>
        <tr>
          <th scope="col">Type</th>
          <th scope="col">Name</th>
          <th scope="col">Data</th>
        </tr>
      </thead>
      <tbody>
        {records.map((r, i) => (
          <tr key={`${r.type}-${r.data}-${i}`}>
            <td className="uscan-mono">{r.type}</td>
            <td className="uscan-mono">{r.name}</td>
            <td className="uscan-mono">{r.data}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function IpDetail({ ipInfo }) {
  if (!ipInfo || typeof ipInfo !== 'object') {
    return <p className="uscan-empty">No IP geolocation available (lookup failed or no A record).</p>
  }
  const flag = ipInfo.country_code
    ? String.fromCodePoint(...[...ipInfo.country_code].map((c) => 127397 + c.charCodeAt(0)))
    : ''
  return (
    <ul className="uscan-kv">
      <li>
        <span>IP address</span>
        <strong className="uscan-mono">
          {ipInfo.ip} {flag && <span aria-hidden="true">{flag}</span>}
        </strong>
      </li>
      <li>
        <span>Location</span>
        <strong>
          {[ipInfo.city, ipInfo.country].filter(Boolean).join(', ') || 'unknown'}
        </strong>
      </li>
      <li>
        <span>ASN</span>
        <strong className="uscan-mono">{ipInfo.asn || '—'}</strong>
      </li>
      <li>
        <span>ISP / org</span>
        <strong>{ipInfo.org || ipInfo.isp || '—'}</strong>
      </li>
    </ul>
  )
}

function CertDetail({ cert }) {
  if (!cert || typeof cert !== 'object') {
    return <p className="uscan-empty">No certificate data (crt.sh unreachable or no entries).</p>
  }
  return (
    <ul className="uscan-kv">
      <li>
        <span>Common name</span>
        <strong className="uscan-mono">{cert.common_name || '—'}</strong>
      </li>
      <li>
        <span>Issuer</span>
        <strong>{cert.issuer || '—'}</strong>
      </li>
      <li>
        <span>Valid</span>
        <strong className="uscan-mono">
          {cert.not_before || '?'} → {cert.not_after || '?'}
        </strong>
      </li>
    </ul>
  )
}

function UrlResult({ report }) {
  const page = report.page || {}
  const ipInfo = report.ip_info
  const flag =
    ipInfo && ipInfo.country_code
      ? String.fromCodePoint(...[...ipInfo.country_code].map((c) => 127397 + c.charCodeAt(0)))
      : ''
  const nDns = report.dns?.records?.length || 0
  const nFindings = report.findings?.length || 0

  return (
    <article className="uscan-result">
      <header className="uscan-head">
        <div>
          <h3 className="uscan-host">{report.host}</h3>
          <p className="uscan-sub">
            {ipInfo?.ip ? (
              <>
                <span className="uscan-mono">{ipInfo.ip}</span> {flag && <span aria-hidden="true">{flag}</span>} ·{' '}
              </>
            ) : null}
            <VerdictBadge verdict={report.verdict} />
          </p>
        </div>
        <p className="uscan-scanned">{report.scanned_at}</p>
      </header>

      <div className="uscan-grid">
        <div className="uscan-col">
          <section className="uscan-card" aria-label="Summary">
            <h4>Summary</h4>
            <p className="uscan-summary">
              The page returned{' '}
              <strong>{page.status ? `HTTP ${page.status}` : 'no HTTP response'}</strong>
              {page.title ? (
                <>
                  {' '}with the title <strong>“{page.title}”</strong>
                </>
              ) : null}
              . {nDns} DNS record{nDns === 1 ? '' : 's'} resolved
              {ipInfo?.org ? (
                <>
                  {' '}
                  to <strong>{ipInfo.ip}</strong> in <strong>{ipInfo.country || 'unknown'}</strong>{' '}
                  ({ipInfo.org})
                </>
              ) : null}
              . {nFindings} heuristic finding{nFindings === 1 ? '' : 's'} from the offline link
              scanner.
            </p>
            <ul className="uscan-kv">
              <li>
                <span>Effective URL</span>
                <strong className="uscan-mono uscan-wrap">{page.final_url || report.url}</strong>
              </li>
              {page.server ? (
                <li>
                  <span>Server</span>
                  <strong className="uscan-mono">{page.server}</strong>
                </li>
              ) : null}
              {page.content_type ? (
                <li>
                  <span>Content type</span>
                  <strong className="uscan-mono">{page.content_type}</strong>
                </li>
              ) : null}
            </ul>
          </section>

          <section className="uscan-card" aria-label="Findings">
            <h4>Findings</h4>
            {nFindings === 0 ? (
              <p className="uscan-empty">No heuristic findings — verdict clean.</p>
            ) : (
              <ul className="link-list">
                {report.findings.map((f, i) => (
                  <li key={i} className={`link-row finding ${VERDICT_TONE[f.severity] || 'sev-low'}`}>
                    <div className="link-row-head">
                      <span className="sev-badge sev-badge-sm">{f.severity}</span>
                      <code className="uscan-mono">{f.rule}</code>
                    </div>
                    <p className="finding-desc">{f.detail}</p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {report.errors?.length > 0 && (
            <section className="uscan-card uscan-warn" aria-label="Source warnings">
              <h4>Source warnings</h4>
              <ul className="uscan-errors">
                {report.errors.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <div className="uscan-col">
          <section className="uscan-card" aria-label="Screenshot">
            <h4>Screenshot</h4>
            <a href={report.screenshot_url} target="_blank" rel="noreferrer">
              <img
                className="uscan-shot"
                src={report.screenshot_url}
                alt={`Screenshot of ${report.host}`}
                loading="lazy"
              />
            </a>
          </section>

          <section className="uscan-card" aria-label="Domain and IP information">
            <h4>Domain &amp; IP information</h4>
            <IpDetail ipInfo={ipInfo} />
          </section>

          <section className="uscan-card" aria-label="DNS records">
            <h4>DNS records</h4>
            <DnsTable records={report.dns?.records} />
          </section>

          <section className="uscan-card" aria-label="TLS certificate">
            <h4>TLS certificate</h4>
            <CertDetail cert={report.cert} />
          </section>
        </div>
      </div>
    </article>
  )
}

export default function UrlScanner() {
  const [url, setUrl] = useState('')
  const [report, setReport] = useState(null)
  const [state, setState] = useState('idle') // 'idle' | 'loading' | 'error'
  const [error, setError] = useState(null)

  async function scan(e) {
    e?.preventDefault()
    const target = url.trim()
    if (!target) {
      setError('enter a URL first')
      setState('error')
      return
    }
    setState('loading')
    setError(null)
    try {
      const res = await fetch(`/api/urlscan?url=${encodeURIComponent(target)}`, {
        headers: { Accept: 'application/json' },
      })
      const body = await res.json().catch(() => null)
      if (!res.ok) throw new Error(body?.error || `scan failed (HTTP ${res.status})`)
      if (!body || typeof body !== 'object' || !('verdict' in body)) {
        throw new Error('response was not a urlscan report')
      }
      setReport(body)
      setState('idle')
    } catch (err) {
      setError(err.message || 'could not reach the scanner')
      setState('error')
    }
  }

  return (
    <section className="report-section" aria-label="URL scan report" id="urlscan">
      <div className="section-head">
        <h2>URL scan</h2>
        <span className="section-meta">urlscan.io-style report · live fetches via dns.google, ipwho.is, crt.sh</span>
      </div>
      <form className="link-form" onSubmit={scan}>
        <label className="visually-hidden" htmlFor="uscan-url">
          URL to scan
        </label>
        <input
          id="uscan-url"
          className="link-input"
          type="text"
          inputMode="url"
          placeholder="https://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button className="btn btn-primary" type="submit" disabled={state === 'loading'}>
          {state === 'loading' ? 'scanning…' : 'Scan URL'}
        </button>
      </form>

      {state === 'error' && (
        <div className="scan-error" role="alert">
          <strong>Scan failed:</strong> {error}
          <div className="scan-error-actions">
            <button className="filter-btn" onClick={() => scan()}>
              try again
            </button>
          </div>
        </div>
      )}

      {state === 'loading' && (
        <div className="uscan-result" role="status" aria-label="Loading scan report">
          <span className="skeleton skeleton-num" />
          <span className="skeleton skeleton-badge" />
          <span className="skeleton uscan-skel-card" />
        </div>
      )}

      {state === 'idle' && report && <UrlResult report={report} />}

      {state === 'idle' && !report && (
        <div className="empty" role="status">
          <p>No URL scanned yet.</p>
          <p className="empty-hint">
            Enter a URL above for a urlscan.io-style report. This makes outbound requests: the
            page itself is fetched, and dns.google, ipwho.is and crt.sh are queried. Use{' '}
            <code>hookscan links</code> for the fully offline heuristics-only scan.
          </p>
        </div>
      )}
    </section>
  )
}
