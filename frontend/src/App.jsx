import { useState, useRef, useEffect } from 'react'
import ScoreHeader from './components/ScoreHeader'
import ScannerSection from './components/ScannerSection'
import Recommendations from './components/Recommendations'
import ContactPage from './components/ContactPage'

const SCANNER_NAMES = [
  'SSL/TLS',
  'Security Headers',
  'Technology Detection',
  'File Exposure',
  'DNS & Domain',
]

const STATES = { IDLE: 'idle', SCANNING: 'scanning', DONE: 'done', ERROR: 'error' }

export default function App() {
  const [url, setUrl]       = useState('')
  const [state, setState]   = useState(STATES.IDLE)
  const [steps, setSteps]   = useState([])
  const [report, setReport] = useState(null)
  const [error, setError]   = useState('')
  const [noobify, setNoobify] = useState(false)
  const [tab, setTab]       = useState('scanner') // 'scanner' | 'contact'
  const [theme, setTheme]   = useState(() =>
    localStorage.getItem('theme') || 'dark'
  )
  const esRef = useRef(null)

  // Apply theme to <html>
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  function toggleTheme() {
    setTheme(t => t === 'dark' ? 'light' : 'dark')
  }

  function initSteps() {
    return SCANNER_NAMES.map(name => ({ name, status: 'pending' }))
  }

  function updateStep(name, status) {
    setSteps(prev => prev.map(s => s.name === name ? { ...s, status } : s))
  }

  function handleSubmit(e) {
    e.preventDefault()
    if (!url.trim()) return

    setState(STATES.SCANNING)
    setReport(null)
    setError('')
    setNoobify(false)
    setSteps(initSteps())

    if (esRef.current) esRef.current.close()

    const encoded = encodeURIComponent(url.trim())
    const es = new EventSource(`/scan/stream?url=${encoded}`)
    esRef.current = es

    es.addEventListener('progress', e => {
      const data = JSON.parse(e.data)
      if (data.status === 'running') updateStep(data.name, 'running')
      if (data.status === 'done')    updateStep(data.name, data.error ? 'error' : 'done')
    })

    es.addEventListener('complete', e => {
      setReport(JSON.parse(e.data))
      setState(STATES.DONE)
      es.close()
    })

    es.onerror = () => {
      setError('Could not connect to the scanner. Make sure the API server is running.')
      setState(STATES.ERROR)
      es.close()
    }
  }

  function reset() {
    if (esRef.current) esRef.current.close()
    setState(STATES.IDLE)
    setReport(null)
    setError('')
    setSteps([])
    setNoobify(false)
  }

  return (
    <div className="layout">
      <nav className="nav">
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <span className="nav-logo" style={{ cursor: 'pointer' }} onClick={() => { reset(); setTab('scanner') }}>
            Slopsicurity
          </span>
          <button
            className={`nav-link ${tab === 'scanner' ? 'active' : ''}`}
            onClick={() => setTab('scanner')}
          >
            Scanner
          </button>
          <button
            className={`nav-link ${tab === 'contact' ? 'active' : ''}`}
            onClick={() => setTab('contact')}
          >
            Contact
          </button>
        </div>
        <div className="nav-right">
          <label className="toggle-wrap" onClick={toggleTheme}>
            <span className="toggle-label">{theme === 'dark' ? 'Dark' : 'Light'}</span>
            <div className={`toggle-track ${theme === 'light' ? 'on' : ''}`}>
              <div className="toggle-thumb" />
            </div>
          </label>
        </div>
      </nav>

      {tab === 'contact' && (
        <ContactPage lastReport={report} />
      )}

      {tab === 'scanner' && state === STATES.IDLE && (
        <div className="fade-in">
          <div className="hero">
            <h1 className="hero-title">Security scan.<br />No nonsense.</h1>
            <p className="hero-sub">
              Passive, non-invasive checks. SSL, headers, DNS, file exposure, tech detection.
              Results in seconds.
            </p>
          </div>
          <form className="scan-form" onSubmit={handleSubmit}>
            <input
              className="url-input"
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={e => setUrl(e.target.value)}
              spellCheck={false}
              autoFocus
            />
            <button className="scan-btn" type="submit" disabled={!url.trim()}>
              Scan
            </button>
          </form>
          <p className="scan-hint">look, don't touch.</p>
        </div>
      )}

      {tab === 'scanner' && state === STATES.SCANNING && (
        <div className="progress-block fade-in">
          <p className="progress-label">Scanning {url}</p>
          <div className="scanner-steps">
            {steps.map(step => (
              <div key={step.name} className={`scanner-step ${step.status}`}>
                {step.status === 'running'
                  ? <span className="step-spinner" />
                  : <span className="step-dot" />
                }
                <span>{step.name}</span>
                {step.status === 'done'  && <span style={{ marginLeft: 'auto', fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--pass)' }}>done</span>}
                {step.status === 'error' && <span style={{ marginLeft: 'auto', fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--fail)' }}>error</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === 'scanner' && state === STATES.ERROR && (
        <div className="fade-in">
          <div className="error-block">{error}</div>
          <button className="new-scan-btn" onClick={reset}>Try again</button>
        </div>
      )}

      {tab === 'scanner' && state === STATES.DONE && report && (
        <div className="fade-in">
          <div className="results-toolbar">
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="new-scan-btn" onClick={reset}>← New scan</button>
              <button className="new-scan-btn" onClick={() => setTab('contact')}>Get help</button>
            </div>
            <label className="toggle-wrap" onClick={() => setNoobify(n => !n)}>
              <span className="toggle-label">Noobify</span>
              <div className={`toggle-track ${noobify ? 'noobify-on' : ''}`}>
                <div className="toggle-thumb" />
              </div>
            </label>
          </div>

          <ScoreHeader report={report} />

          <div className="sections">
            {report.scanners.map(scanner => (
              <ScannerSection
                key={scanner.name}
                scanner={scanner}
                noobify={noobify}
              />
            ))}
          </div>

          {report.recommendations.length > 0 && (
            <Recommendations items={report.recommendations} noobify={noobify} />
          )}
        </div>
      )}
    </div>
  )
}
