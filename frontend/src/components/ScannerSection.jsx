import { useState } from 'react'
import { noobify } from '../noobify'

export default function ScannerSection({ scanner, noobify: noobifyOn }) {
  const [open, setOpen] = useState(false)

  const pct = scanner.max_score > 0
    ? Math.round(scanner.score / scanner.max_score * 100)
    : 0

  const barColor = pct >= 80 ? 'var(--pass)'
    : pct >= 50 ? 'var(--warn)'
    : 'var(--fail)'

  const realFindings = scanner.findings.filter(f => f.max_score > 0)
  const infoFindings = scanner.findings.filter(f => f.max_score === 0)

  return (
    <div className="scanner-card">
      <button className="scanner-card-header" onClick={() => setOpen(o => !o)}>
        <span className="scanner-name">{scanner.name}</span>
        <div className="scanner-header-right">
          {scanner.max_score > 0 && (
            <>
              <span className="scanner-score-badge">
                {scanner.score}/{scanner.max_score}
              </span>
              <div className="scanner-mini-bar">
                <div
                  className="scanner-mini-fill"
                  style={{ width: `${pct}%`, background: barColor }}
                />
              </div>
            </>
          )}
          <span className={`chevron ${open ? 'open' : ''}`}>▼</span>
        </div>
      </button>

      {open && (
        <div className="scanner-card-body">
          {scanner.error && (
            <div className="scanner-error">Error: {scanner.error}</div>
          )}

          {realFindings.map(f => {
            const plain = noobify(f.check_id, f.detail)
            return (
              <div key={f.check_id} className="finding-row">
                <span className={`finding-icon ${f.passed ? 'icon-pass' : 'icon-fail'}`}>
                  {f.passed ? '✓' : '✗'}
                </span>
                <div className="finding-body">
                  <div className="finding-label">{f.label}</div>
                  {noobifyOn && plain
                    ? <p className="finding-noob">{plain}</p>
                    : <div className="finding-detail">{f.detail}</div>
                  }
                </div>
                <span className={`finding-pts ${f.passed ? 'pts-pass' : 'pts-fail'}`}>
                  {f.passed ? `+${f.score}` : `0/${f.max_score}`}
                </span>
              </div>
            )
          })}

          {infoFindings.map(f => (
            <div key={f.check_id} className="finding-row informational">
              <span className="finding-icon icon-info">ℹ</span>
              <div className="finding-body">
                <div className="finding-label">{f.label}</div>
                <div className="finding-detail">{f.detail}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
