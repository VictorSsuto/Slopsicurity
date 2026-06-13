import { useState } from 'react'
import { noobify } from '../noobify'

export default function Recommendations({ items, noobify: noobifyOn }) {
  const [expanded, setExpanded] = useState({})

  function toggle(id) {
    setExpanded(prev => ({ ...prev, [id]: !prev[id] }))
  }

  return (
    <div className="recommendations">
      <div className="reco-header">
        <span className="reco-title">Recommendations</span>
        <span className="reco-count">{items.length}</span>
      </div>

      {items.map((item, i) => {
        const plain      = noobify(item.check_id, item.recommendation)
        const hasSnippet = Boolean(item.code_snippet)
        const snippetOpen = expanded[item.check_id]

        return (
          <div key={item.check_id} className="reco-item">
            <div className="reco-item-header">
              <span className="reco-num">{String(i + 1).padStart(2, '0')}</span>
              <span className="reco-label">{item.label}</span>
              <span className="reco-pts">−{item.impact_points} pts</span>
            </div>

            {noobifyOn && plain
              ? <p className="reco-noob">{plain}</p>
              : <p className="reco-text">{item.recommendation}</p>
            }

            {hasSnippet && (
              <div className="reco-snippet-wrap">
                <button
                  className="reco-snippet-toggle"
                  onClick={() => toggle(item.check_id)}
                >
                  {snippetOpen ? '▲ Hide fix' : '▼ Show fix'}
                </button>
                {snippetOpen && (
                  <pre className="reco-snippet">{item.code_snippet}</pre>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
