import { noobify } from '../noobify'

export default function Recommendations({ items, noobify: noobifyOn }) {
  return (
    <div className="recommendations">
      <div className="reco-header">
        <span className="reco-title">Recommendations</span>
        <span className="reco-count">{items.length}</span>
      </div>

      {items.map((item, i) => {
        const plain = noobify(item.check_id, item.recommendation)
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
          </div>
        )
      })}
    </div>
  )
}
