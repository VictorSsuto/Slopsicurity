import { useState } from 'react'

const HISTORY_KEY = 'slopsicurity_history'
const MAX_ENTRIES = 20

export function saveToHistory(report) {
  try {
    const existing = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]')
    const entry = {
      id:         Date.now(),
      timestamp:  new Date().toISOString(),
      url:        report.url,
      grade:      report.score.grade,
      percentage: report.score.percentage,
      total:      report.score.total,
      max:        report.score.max,
      report,
    }
    const updated = [entry, ...existing].slice(0, MAX_ENTRIES)
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated))
  } catch { /* ignore quota errors */ }
}

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]') }
  catch { return [] }
}

function gradeClass(grade) {
  if (grade === 'A+' || grade === 'A') return 'grade-A'
  if (grade === 'B' || grade === 'C') return 'grade-B'
  return 'grade-F'
}

function fmtDate(iso) {
  const d = new Date(iso)
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
    + ' · ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

function buildFindingMap(report) {
  const map = {}
  for (const scanner of report.scanners) {
    for (const f of scanner.findings) {
      if (f.max_score > 0) map[f.check_id] = { passed: f.passed, label: f.label }
    }
  }
  return map
}

function computeDiff(entryA, entryB) {
  // A = older, B = newer
  const mapA = buildFindingMap(entryA.report)
  const mapB = buildFindingMap(entryB.report)
  const allIds = new Set([...Object.keys(mapA), ...Object.keys(mapB)])
  const fixed   = []
  const broke   = []
  for (const id of allIds) {
    const a = mapA[id]
    const b = mapB[id]
    if (!a || !b) continue
    if (!a.passed && b.passed)  fixed.push(b.label)
    if (a.passed  && !b.passed) broke.push(b.label)
  }
  return { fixed, broke }
}

export default function HistoryPage({ onLoadReport }) {
  const [history, setHistory]       = useState(loadHistory)
  const [selected, setSelected]     = useState([])   // up to 2 entry IDs
  const [diff, setDiff]             = useState(null)

  function clearHistory() {
    localStorage.removeItem(HISTORY_KEY)
    setHistory([])
    setSelected([])
    setDiff(null)
  }

  function toggleSelect(id) {
    setDiff(null)
    setSelected(prev => {
      if (prev.includes(id)) return prev.filter(x => x !== id)
      if (prev.length >= 2)  return [prev[1], id]  // shift oldest off
      return [...prev, id]
    })
  }

  function runDiff() {
    const [a, b] = selected.map(id => history.find(e => e.id === id))
    if (!a || !b) return
    // Sort chronologically: older first
    const [older, newer] = a.timestamp < b.timestamp ? [a, b] : [b, a]
    setDiff({ older, newer, ...computeDiff(older, newer) })
  }

  if (history.length === 0) {
    return (
      <div className="hist-empty fade-in">
        <p className="hist-empty-title">No scans yet</p>
        <p className="hist-empty-sub">Run a scan and your results will appear here automatically.</p>
      </div>
    )
  }

  return (
    <div className="hist-page fade-in">
      <div className="hist-toolbar">
        <div>
          <span className="hist-toolbar-title">Scan history</span>
          <span className="hist-count">{history.length} / {MAX_ENTRIES}</span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {selected.length === 2 && (
            <button className="hist-compare-btn" onClick={runDiff}>
              Compare selected
            </button>
          )}
          <button className="hist-clear-btn" onClick={clearHistory}>
            Clear all
          </button>
        </div>
      </div>

      {selected.length > 0 && selected.length < 2 && (
        <p className="hist-select-hint">Select one more scan to compare</p>
      )}

      {/* Diff panel */}
      {diff && (
        <div className="hist-diff fade-in">
          <div className="hist-diff-header">
            <div className="hist-diff-side">
              <span className="hist-diff-label">Before</span>
              <span className={`hist-diff-grade ${gradeClass(diff.older.grade)}`}>{diff.older.grade}</span>
              <span className="hist-diff-score">{diff.older.percentage}%</span>
              <span className="hist-diff-url">{diff.older.url}</span>
              <span className="hist-diff-date">{fmtDate(diff.older.timestamp)}</span>
            </div>
            <span className="hist-diff-arrow">→</span>
            <div className="hist-diff-side">
              <span className="hist-diff-label">After</span>
              <span className={`hist-diff-grade ${gradeClass(diff.newer.grade)}`}>{diff.newer.grade}</span>
              <span className="hist-diff-score">{diff.newer.percentage}%</span>
              <span className="hist-diff-url">{diff.newer.url}</span>
              <span className="hist-diff-date">{fmtDate(diff.newer.timestamp)}</span>
            </div>
          </div>

          {diff.fixed.length === 0 && diff.broke.length === 0 ? (
            <p className="hist-diff-none">No changes detected between these two scans.</p>
          ) : (
            <div className="hist-diff-changes">
              {diff.fixed.map(label => (
                <div key={label} className="hist-diff-row hist-diff-fixed">
                  <span className="hist-diff-icon">✓</span>
                  <span>{label}</span>
                  <span className="hist-diff-tag">Fixed</span>
                </div>
              ))}
              {diff.broke.map(label => (
                <div key={label} className="hist-diff-row hist-diff-broke">
                  <span className="hist-diff-icon">✗</span>
                  <span>{label}</span>
                  <span className="hist-diff-tag">Regressed</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* History list */}
      <div className="hist-list">
        {history.map(entry => {
          const isSelected = selected.includes(entry.id)
          return (
            <div
              key={entry.id}
              className={`hist-row ${isSelected ? 'hist-row--selected' : ''}`}
            >
              <button
                className="hist-select-box"
                onClick={() => toggleSelect(entry.id)}
                title={isSelected ? 'Deselect' : 'Select to compare'}
              >
                <span className={`hist-checkbox ${isSelected ? 'hist-checkbox--on' : ''}`} />
              </button>

              <span className={`hist-grade ${gradeClass(entry.grade)}`}>{entry.grade}</span>

              <div className="hist-meta">
                <span className="hist-url">{entry.url}</span>
                <span className="hist-date">{fmtDate(entry.timestamp)}</span>
              </div>

              <span className="hist-pct">{entry.percentage}%</span>

              <button
                className="hist-load-btn"
                onClick={() => onLoadReport(entry.report)}
                title="Load this report"
              >
                View →
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}
