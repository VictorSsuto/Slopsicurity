export default function ScoreHeader({ report }) {
  const { score } = report
  const grade = score.grade.replace('+', '-plus')
  const passes = report.scanners
    .flatMap(s => s.findings)
    .filter(f => f.passed && f.max_score > 0).length
  const fails = report.recommendations.length

  return (
    <div className="score-header" style={{ marginBottom: 24 }}>
      <div className="grade-block">
        <span className={`grade-letter grade-${grade}`}>{score.grade}</span>
        <span className="grade-desc">{score.grade_description}</span>
      </div>

      <div className="score-right">
        <span className="score-url">{report.url}</span>

        <div className="score-numbers">
          <span className="score-value">{score.total}</span>
          <span className="score-max">/ {score.max}</span>
          <span className="score-pct">{score.percentage}%</span>
        </div>

        <div className="score-bar-track">
          <div
            className={`score-bar-fill bar-${grade}`}
            style={{ width: `${score.percentage}%` }}
          />
        </div>

        <div className="score-summary">
          <span className="summary-pass">✓ {passes} passed</span>
          <span className="summary-fail">✗ {fails} failed</span>
        </div>
      </div>
    </div>
  )
}
