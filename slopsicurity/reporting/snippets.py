"""
Server-specific fix snippets for each failing check.

json_out.py calls get_snippet(check_id, detected_servers) to attach
a copy-pasteable config line to each recommendation.
"""
from typing import Optional

# Priority order for server selection
SERVER_PRIORITY = ["cloudflare", "nginx", "apache", "varnish", "asp_net"]

# check_id → {server_key → snippet}
SNIPPETS: dict[str, dict[str, str]] = {

    # ── Security Headers ─────────────────────────────────────────────────────

    "hdr_hsts": {
        "nginx":      'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        "apache":     'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        "cloudflare": "Cloudflare → SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS) → Enable",
        "asp_net":    'In Web.config:\n<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />',
        "default":    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "hdr_csp": {
        "nginx":      "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';\" always;",
        "apache":     "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self';\"",
        "cloudflare": "Cloudflare → Rules → Transform Rules → Modify Response Header → Add Content-Security-Policy",
        "asp_net":    "In Web.config:\n<add name=\"Content-Security-Policy\" value=\"default-src 'self'\" />",
        "default":    "Content-Security-Policy: default-src 'self'",
    },
    "hdr_xfo": {
        "nginx":      'add_header X-Frame-Options "DENY" always;',
        "apache":     'Header always set X-Frame-Options "DENY"',
        "cloudflare": "Cloudflare → Rules → Transform Rules → Modify Response Header → Add X-Frame-Options: DENY",
        "asp_net":    'In Web.config:\n<add name="X-Frame-Options" value="DENY" />',
        "default":    "X-Frame-Options: DENY",
    },
    "hdr_xcto": {
        "nginx":      'add_header X-Content-Type-Options "nosniff" always;',
        "apache":     'Header always set X-Content-Type-Options "nosniff"',
        "cloudflare": "Cloudflare → Rules → Transform Rules → Modify Response Header → Add X-Content-Type-Options: nosniff",
        "asp_net":    'In Web.config:\n<add name="X-Content-Type-Options" value="nosniff" />',
        "default":    "X-Content-Type-Options: nosniff",
    },
    "hdr_rp": {
        "nginx":      'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "apache":     'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        "cloudflare": "Cloudflare → Rules → Transform Rules → Modify Response Header → Add Referrer-Policy: strict-origin-when-cross-origin",
        "asp_net":    'In Web.config:\n<add name="Referrer-Policy" value="strict-origin-when-cross-origin" />',
        "default":    "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "hdr_pp": {
        "nginx":      'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
        "apache":     'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
        "cloudflare": "Cloudflare → Rules → Transform Rules → Modify Response Header → Add Permissions-Policy",
        "asp_net":    'In Web.config:\n<add name="Permissions-Policy" value="geolocation=(), microphone=(), camera=()" />',
        "default":    "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "hdr_xxp": {
        "nginx":      "add_header X-XSS-Protection \"0\" always;  # Intentional — disables the buggy legacy filter",
        "apache":     "Header always set X-XSS-Protection \"0\"  # Intentional — modern recommendation",
        "cloudflare": "Cloudflare → Rules → Transform Rules → Modify Response Header → Add X-XSS-Protection: 0",
        "default":    "X-XSS-Protection: 0  # Intentionally disabling — the legacy filter has known exploits",
    },
    "hdr_server_leak": {
        "nginx":      "server_tokens off;  # Add to http{} block in nginx.conf",
        "apache":     "ServerTokens Prod\nServerSignature Off  # Add to httpd.conf",
        "cloudflare": "Cloudflare automatically replaces the Server header — no action needed",
        "default":    "Configure your server to suppress or genericize the Server response header.",
    },
    "hdr_powered_leak": {
        "nginx":      "# X-Powered-By usually comes from the app, not nginx\n# PHP: expose_php = Off  (in php.ini)",
        "apache":     "Header unset X-Powered-By\n# Or for PHP: expose_php = Off  (in php.ini)",
        "cloudflare": "Cloudflare → Rules → Transform Rules → Modify Response Header → Remove X-Powered-By",
        "default":    "Remove X-Powered-By in your application framework or web server config.",
    },
    "hdr_aspnet_leak": {
        "asp_net":    'In Web.config:\n<httpRuntime enableVersionHeader="false" />\n<!-- Also remove X-Powered-By: -->\n<remove name="X-Powered-By" />',
        "default":    'In Web.config: <httpRuntime enableVersionHeader="false" />',
    },

    # ── SSL / TLS ────────────────────────────────────────────────────────────

    "ssl_https": {
        "nginx":      "server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}",
        "apache":     "<VirtualHost *:80>\n  ServerName example.com\n  Redirect permanent / https://example.com/\n</VirtualHost>",
        "cloudflare": "Cloudflare → SSL/TLS → Edge Certificates → Always Use HTTPS → Enable",
        "default":    "Redirect all HTTP to HTTPS. Obtain a free certificate from letsencrypt.org",
    },
    "ssl_tls_version": {
        "nginx":      "ssl_protocols TLSv1.2 TLSv1.3;  # In your server{} or http{} block",
        "apache":     "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1  # In httpd.conf or ssl.conf",
        "cloudflare": "Cloudflare → SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2",
        "default":    "Disable TLS 1.0 and 1.1. Enable TLS 1.2 and 1.3 only.",
    },
    "ssl_cert_valid": {
        "nginx":      "# Renew with Certbot:\ncertbot renew --nginx",
        "apache":     "# Renew with Certbot:\ncertbot renew --apache",
        "cloudflare": "Cloudflare manages your edge certificate automatically. Check your origin certificate.",
        "default":    "Renew your SSL certificate. Use certbot or your hosting panel.",
    },
    "ssl_cert_expiry": {
        "nginx":      "# Set up auto-renewal:\ncertbot renew --nginx\n# Add to cron: 0 0 * * * certbot renew --quiet",
        "apache":     "# Set up auto-renewal:\ncertbot renew --apache\n# Add to cron: 0 0 * * * certbot renew --quiet",
        "cloudflare": "Cloudflare auto-renews edge certificates. Check your origin cert expiry.",
        "default":    "Enable auto-renewal. With Let's Encrypt: certbot renew (cron it to run daily).",
    },

    # ── DNS ──────────────────────────────────────────────────────────────────

    "dns_spf": {
        "default": "Add a TXT record to your DNS zone:\n  Name: @\n  Value: v=spf1 include:_spf.google.com ~all\n\n(Replace the include: with your mail provider's SPF.)",
    },
    "dns_dmarc": {
        "default": "Add a TXT record to your DNS zone:\n  Name: _dmarc\n  Value: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
    },
    "dns_caa": {
        "default": "Add a CAA record to your DNS zone:\n  Name: @\n  Type: CAA\n  Value: 0 issue \"letsencrypt.org\"\n\n(Use your actual CA — e.g. digicert.com, sectigo.com)",
    },

    # ── Cookie Security ──────────────────────────────────────────────────────

    "cookie_httponly": {
        "nginx":         "proxy_cookie_flags ~ HttpOnly Secure SameSite=Strict;",
        "apache":        'Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly"',
        "django":        "SESSION_COOKIE_HTTPONLY = True  # settings.py",
        "laravel_php":   "# config/session.php:\n'http_only' => true,",
        "ruby_on_rails": "config.session_store :cookie_store, httponly: true  # application.rb",
        "default":       "Set HttpOnly flag on all session cookies:\nSet-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict",
    },
    "cookie_secure": {
        "nginx":         "proxy_cookie_flags ~ HttpOnly Secure SameSite=Strict;",
        "apache":        'Header always edit Set-Cookie ^(.*)$ "$1; Secure"',
        "django":        "SESSION_COOKIE_SECURE = True  # settings.py",
        "laravel_php":   "# config/session.php:\n'secure' => true,",
        "ruby_on_rails": "config.session_store :cookie_store, secure: Rails.env.production?  # application.rb",
        "default":       "Set Secure flag on all cookies:\nSet-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict",
    },
    "cookie_samesite": {
        "nginx":         "proxy_cookie_flags ~ HttpOnly Secure SameSite=Strict;",
        "apache":        'Header always edit Set-Cookie ^(.*)$ "$1; SameSite=Strict"',
        "django":        "SESSION_COOKIE_SAMESITE = 'Strict'  # settings.py",
        "laravel_php":   "# config/session.php:\n'same_site' => 'strict',",
        "ruby_on_rails": "config.session_store :cookie_store, same_site: :strict  # application.rb",
        "default":       "Set SameSite=Strict on all cookies:\nSet-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict",
    },
}

# All file_* checks share the same server-block-deny pattern
_FILE_BLOCK: dict[str, str] = {
    "nginx":  "location ~ /({path}) {{\n  deny all;\n  return 404;\n}}",
    "apache": '<FilesMatch "^({path})$">\n  Require all denied\n</FilesMatch>',
    "default": "Block access to this path in your web server or application config.",
}


def _file_path_from_check_id(check_id: str) -> str:
    """Recover a human-readable path hint from a file_* check_id."""
    slug = check_id.removeprefix("file_")
    return slug.replace("_", ".").replace("..", "/")


def get_snippet(check_id: str, detected_servers: set) -> Optional[str]:
    """
    Return the most relevant fix snippet for a given check_id, choosing the
    best match from the caller's set of detected server/framework tech names.

    detected_servers should contain normalised keys like 'nginx', 'apache',
    'cloudflare', 'asp_net', 'django', 'laravel_php', 'ruby_on_rails'.
    """
    # File-exposure checks share a generic deny-all pattern
    if check_id.startswith("file_"):
        path_hint = _file_path_from_check_id(check_id)
        for server in SERVER_PRIORITY:
            if server in detected_servers and server in _FILE_BLOCK:
                tpl = _FILE_BLOCK[server]
                return tpl.replace("{path}", path_hint) if "{path}" in tpl else tpl
        return _FILE_BLOCK["default"].replace("{path}", path_hint)

    table = SNIPPETS.get(check_id)
    if not table:
        return None

    # Walk priority list, then fall back to detected frameworks, then default
    all_keys = SERVER_PRIORITY + ["django", "laravel_php", "ruby_on_rails"]
    for key in all_keys:
        if key in detected_servers and key in table:
            return table[key]

    return table.get("default")
