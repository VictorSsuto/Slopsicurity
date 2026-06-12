import { useState } from 'react'

const CALENDLY_URL = 'https://calendly.com/slopsicurity' // replace with your real link

export default function ContactPage({ lastReport }) {
  const [form, setForm] = useState({
    name: '',
    email: '',
    website: lastReport?.url || '',
    message: lastReport
      ? `Hi,\n\nI just scanned ${lastReport.url} and received a grade of ${lastReport.score.grade} (${lastReport.score.percentage}%).\n\nI'd like to book a consultation to go over the results and understand what needs fixing:\n${lastReport.recommendations.slice(0, 3).map(r => `- ${r.label}`).join('\n')}\n\nLooking forward to hearing from you.`
      : '',
  })
  const [status, setStatus] = useState('idle') // idle | sending | sent | error
  const [errorMsg, setErrorMsg] = useState('')

  function set(field) {
    return e => setForm(f => ({ ...f, [field]: e.target.value }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setStatus('sending')
    setErrorMsg('')

    try {
      const res = await fetch('/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: form.name,
          email: form.email,
          website: form.website,
          message: form.message,
          scan_grade: lastReport?.score.grade || null,
          scan_pct: lastReport?.score.percentage || null,
        }),
      })

      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.detail || 'Something went wrong.')
      }

      setStatus('sent')
    } catch (err) {
      setErrorMsg(err.message)
      setStatus('error')
    }
  }

  if (status === 'sent') {
    return (
      <div className="contact-sent fade-in">
        <div className="contact-sent-icon">✓</div>
        <h2 className="contact-sent-title">Message sent</h2>
        <p className="contact-sent-sub">
          We'll get back to you at <strong>{form.email}</strong> within one business day.
        </p>
        <button className="scan-btn" style={{ marginTop: 24 }} onClick={() => setStatus('idle')}>
          Send another
        </button>
      </div>
    )
  }

  return (
    <div className="contact-page fade-in">
      <div className="hero" style={{ marginBottom: 48 }}>
        <h1 className="hero-title">Let's talk.</h1>
        <p className="hero-sub">
          Not sure where to start? Book a free consultation and we'll walk through your results together.
          From there, we'll put together a quote tailored to what you actually need.
        </p>
      </div>

      {/* ── Book a call ─────────────────────────────────── */}
      <div className="contact-card" style={{ marginBottom: 16 }}>
        <div className="contact-card-inner">
          <div>
            <p className="contact-card-title">Free consultation call</p>
            <p className="contact-card-sub">
              A no-commitment 30-minute call where we review your scan results and explain what needs fixing and why.
              If you'd like to move forward, we'll follow up with a personalised quote.
            </p>
          </div>
          <a
            className="scan-btn"
            href={CALENDLY_URL}
            target="_blank"
            rel="noopener noreferrer"
            style={{ textDecoration: 'none', display: 'inline-block' }}
          >
            Schedule →
          </a>
        </div>
      </div>

      {/* ── Divider ─────────────────────────────────────── */}
      <div className="contact-divider">
        <span className="contact-divider-text">or send a message</span>
      </div>

      {/* ── Contact form ────────────────────────────────── */}
      <form className="contact-form" onSubmit={handleSubmit}>
        <div className="contact-row">
          <div className="contact-field">
            <label className="contact-label">Name</label>
            <input
              className="contact-input"
              type="text"
              placeholder="Your name"
              value={form.name}
              onChange={set('name')}
              required
            />
          </div>
          <div className="contact-field">
            <label className="contact-label">Email</label>
            <input
              className="contact-input"
              type="email"
              placeholder="you@example.com"
              value={form.email}
              onChange={set('email')}
              required
            />
          </div>
        </div>

        <div className="contact-field">
          <label className="contact-label">Website</label>
          <input
            className="contact-input"
            type="text"
            placeholder="https://example.com"
            value={form.website}
            onChange={set('website')}
          />
        </div>

        <div className="contact-field">
          <label className="contact-label">Message</label>
          <textarea
            className="contact-input contact-textarea"
            placeholder="Tell us what you need help with..."
            value={form.message}
            onChange={set('message')}
            required
            rows={8}
          />
        </div>

        {lastReport && (
          <div className="contact-scan-badge">
            <span className="contact-scan-badge-label">Scan attached</span>
            <span className="contact-scan-badge-url">{lastReport.url}</span>
            <span className="contact-scan-badge-grade">{lastReport.score.grade}</span>
          </div>
        )}

        {status === 'error' && (
          <div className="error-block">{errorMsg}</div>
        )}

        <button
          className="scan-btn"
          type="submit"
          disabled={status === 'sending'}
          style={{ alignSelf: 'flex-start' }}
        >
          {status === 'sending' ? 'Sending...' : 'Send message'}
        </button>
      </form>
    </div>
  )
}
