import { useState } from 'react'

export default function ShareModal({ shareUrl, onClose }) {
  const [copied, setCopied] = useState(false)

  function copyUrl() {
    navigator.clipboard.writeText(shareUrl).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="share-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="share-modal">
        <div className="share-modal-header">
          <span className="share-modal-title">Share this report</span>
          <button className="share-modal-close" onClick={onClose}>✕</button>
        </div>

        <p className="share-modal-desc">
          Anyone with this link can view the full report — no account needed.
          The link expires in 30 days.
        </p>

        <div className="share-url-row">
          <input
            className="share-url-input"
            type="text"
            readOnly
            value={shareUrl}
            onClick={e => e.target.select()}
          />
          <button className="share-copy-btn" onClick={copyUrl}>
            {copied ? '✓ Copied' : 'Copy'}
          </button>
        </div>

        <p className="share-modal-hint">
          Send this to a client to let them view the scan — no scanning required on their end.
        </p>
      </div>
    </div>
  )
}
