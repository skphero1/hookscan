import { useMemo, useState } from 'react'

const SEVERITIES = ['all', 'high', 'medium', 'low']

function describe(f) {
  switch (f.kind) {
    case 'DeviceOpen':
      return `open fd ${f.fd} -> ${f.target}`
    case 'InputGroupAccess':
      return `in group 'input' (gid ${f.gid}) — can open any /dev/input device`
    case 'XtstMapped':
      return 'libXtst mapped — capable of X11 XRecord keystroke capture'
    case 'UinputModuleLoaded':
      return 'uinput kernel module loaded — something can inject synthetic input events'
    default:
      return f.kind
  }
}

function FindingRow({ f }) {
  const where = f.pid ? `pid ${f.pid} · ${f.comm}` : 'kernel'
  return (
    <li className={`finding sev-${f.severity}`}>
      <span className="sev-badge">{f.severity}</span>
      <div className="finding-main">
        <span className="finding-desc">{describe(f)}</span>
        <span className="finding-where">{where}</span>
      </div>
    </li>
  )
}

function SkeletonRows() {
  return (
    <ul className="findings" aria-hidden="true">
      {[76, 60, 68, 48].map((w, i) => (
        <li className="finding" key={i}>
          <span className="skeleton skeleton-badge" />
          <div className="finding-main">
            <span className="skeleton" style={{ width: `${w}%` }} />
            <span className="skeleton" style={{ width: `${w - 20}%` }} />
          </div>
        </li>
      ))}
    </ul>
  )
}

export function ScanReport({ state, report }) {
  const [filter, setFilter] = useState('all')
  const [showJson, setShowJson] = useState(false)

  const findings = useMemo(
    () => (filter === 'all' ? report.findings : report.findings.filter((f) => f.severity === filter)),
    [filter, report],
  )

  const jsonText = useMemo(() => JSON.stringify(report, null, 2), [report])

  return (
    <div className="report">
      <div className="report-controls">
        <div className="filter-group" role="tablist" aria-label="Filter by severity">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              role="tab"
              aria-selected={filter === s}
              className={`filter-btn${filter === s ? ' active' : ''}`}
              onClick={() => setFilter(s)}
            >
              {s}
            </button>
          ))}
        </div>
        <button className="filter-btn json-toggle" aria-pressed={showJson} onClick={() => setShowJson(!showJson)}>
          {showJson ? 'view rendered' : 'view raw JSON'}
        </button>
      </div>

      {state === 'loading' ? (
        <SkeletonRows />
      ) : showJson ? (
        <pre className="json-view" tabIndex={0}>{jsonText}</pre>
      ) : findings.length === 0 ? (
        <div className="empty">
          <p>No findings at this severity. The host looks clean here.</p>
          <button className="filter-btn" onClick={() => setFilter('all')}>
            clear filter
          </button>
        </div>
      ) : (
        <ul className="findings">
          {findings.map((f, i) => (
            <FindingRow f={f} key={`${f.kind}-${f.pid ?? 'k'}-${i}`} />
          ))}
        </ul>
      )}
    </div>
  )
}
