export default function DisclaimerPage() {
  return (
    <div className="how-page fade-in">

      <div className="how-hero">
        <h1 className="how-title">How it works</h1>
        <p className="how-sub">
          Passive, read-only checks. No logins, no payloads, no tricks. Here's exactly what we scan for — and what the results actually mean.
        </p>
      </div>

      <div className="how-body">

        <div className="how-section">
          <span className="how-section-label">The checks</span>
          <div className="how-checks">
            <div className="how-check">
              <span className="how-check-name">SSL / TLS</span>
              <span className="how-check-desc">Is the connection encrypted? Is the certificate valid, not expired, and using a modern TLS version (1.2 or 1.3)?</span>
            </div>
            <div className="how-check">
              <span className="how-check-name">Security Headers</span>
              <span className="how-check-desc">Does the server send CSP, HSTS, X-Frame-Options, Referrer-Policy, and Permissions-Policy? These reduce the blast radius of cross-site scripting, clickjacking, and other common attacks.</span>
            </div>
            <div className="how-check">
              <span className="how-check-name">Technology Detection</span>
              <span className="how-check-desc">Can we fingerprint the software stack from public signals? Identified platforms — especially outdated CMS software like WordPress, Joomla, or Drupal — often carry known, unpatched vulnerabilities.</span>
            </div>
            <div className="how-check">
              <span className="how-check-name">File Exposure</span>
              <span className="how-check-desc">Are sensitive files accidentally public? Things like <code>.env</code>, <code>.git/HEAD</code>, database dumps, and <code>phpinfo.php</code> should never be reachable from the internet.</span>
            </div>
            <div className="how-check">
              <span className="how-check-name">DNS & Domain</span>
              <span className="how-check-desc">Are SPF and DMARC records in place to prevent email spoofing? Is there a CAA record restricting which certificate authorities can issue SSL certificates for your domain?</span>
            </div>
            <div className="how-check">
              <span className="how-check-name">Cookie Security</span>
              <span className="how-check-desc">Do all <code>Set-Cookie</code> headers include the <code>HttpOnly</code>, <code>Secure</code>, and <code>SameSite</code> flags? Missing flags make session cookies vulnerable to XSS theft, plain-HTTP interception, and CSRF attacks.</span>
            </div>
          </div>
        </div>

        <div className="how-divider" />

        <div className="how-section">
          <span className="how-section-label">The score</span>
          <p className="how-prose">
            Each check carries a point value based on its real-world impact. Checks are weighted — a missing Content-Security-Policy (15 pts) counts for more than a missing Permissions-Policy (5 pts) because the risk difference is real. Your total score is divided by the maximum possible and converted to a letter grade: A+ through F.
          </p>
          <p className="how-prose">
            Grades: A+ (95%+), A (80%+), B (65%+), C (50%+), D (30%+), F (below 30%).
          </p>
        </div>

        <div className="how-divider" />

        <div className="how-section">
          <span className="how-section-label">Fix snippets</span>
          <p className="how-prose">
            Every failing recommendation includes a "Show fix" button that expands the exact configuration line for your server. The scanner detects whether you're running nginx, Apache, Cloudflare, Django, Laravel, or another stack — and shows the right snippet for that platform. No more googling "how to add HSTS to nginx."
          </p>
        </div>

        <div className="how-divider" />

        <div className="how-section">
          <span className="how-section-label">Scan history & diff</span>
          <p className="how-prose">
            Every scan is saved locally in your browser. The History tab lists your past scans with grade, score, and timestamp. Select any two and click "Compare selected" to see a diff — which checks went from failing to passing (fixed) and which regressed. This makes it easy to confirm that a config change actually worked before shipping it.
          </p>
        </div>

        <div className="how-divider" />

        <div className="how-section">
          <span className="how-section-label">PDF export</span>
          <p className="how-prose">
            After any scan, the "↓ PDF" button generates a professional one-page report with your score, grade, all findings, and prioritised recommendations — including the fix snippets. Hand it directly to a developer or attach it to a client quote.
          </p>
        </div>

        <div className="how-divider" />

        <div className="how-section">
          <span className="how-section-label">Why high-profile sites still get flags</span>
          <p className="how-prose">
            A failing check doesn't mean a site is insecure. It means our specific rule wasn't satisfied — and there's a real difference between the two.
          </p>
          <p className="how-prose">
            Google, for example, doesn't send an <code>X-Frame-Options</code> header — so a naive check fails. But they use <code>Content-Security-Policy: frame-ancestors 'none'</code> instead, which is the modern replacement and is actually stronger. We detect this and pass the check. Similarly, Google sets <code>X-XSS-Protection: 0</code> to disable the browser's legacy XSS filter — because that filter itself had exploitable bugs. Disabling it is correct. We pass that too.
          </p>
          <p className="how-prose">
            Think of the score as a standardised checklist, not a verdict. A site can pass every check and still have vulnerabilities we don't test for. A site can fail a check because it's doing something better than what we expect. Use the score as a starting point, not a conclusion.
          </p>
        </div>

        <div className="how-divider" />

        <div className="how-section">
          <span className="how-section-label">What we don't do</span>
          <p className="how-prose">
            We don't test for SQL injection, XSS, CSRF, or any active vulnerabilities. We don't authenticate, log in, or access protected pages. We don't send malicious payloads or probe for exploits. We don't store the URLs you submit, share results with third parties, or persist any scan data on our servers — history is stored only in your browser. A high score is not a guarantee of safety.
          </p>
        </div>

        <div className="how-divider" />

        <div className="how-section how-section--legal">
          <span className="how-section-label">Legal</span>
          <p className="how-prose">
            Slopsicurity is for informational purposes only. Scores reflect automated, passive checks and are not a professional security audit, penetration test, or compliance assessment. Results may be inaccurate or incomplete. We accept no liability for actions taken based on scan results. Always consult a qualified security professional before making security decisions.
          </p>
          <p className="how-prose">
            By using this service you confirm you have authorisation to scan the target URL. Scanning sites you don't own or have explicit permission to test may be prohibited in your jurisdiction.
          </p>
        </div>

      </div>
    </div>
  )
}
