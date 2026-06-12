/**
 * Plain-English explanations for every check_id.
 * Shown when the user activates Noobify mode.
 */
const NOOBIFY_MAP = {
  // ── SSL / TLS ──────────────────────────────────────────────────────────────
  ssl_https: (
    "Your site is not using HTTPS. That means any data your visitors send — " +
    "passwords, form fields, personal info — is sent in plain text, like a postcard " +
    "anyone can read. Switch to HTTPS so it travels in a sealed envelope instead."
  ),
  ssl_cert_valid: (
    "Your security certificate has expired or couldn't be read. Browsers will show " +
    "a big red warning page to anyone who visits, which basically tells them 'this site " +
    "is not safe.' Most visitors will leave immediately."
  ),
  ssl_cert_expiry: (
    "Your certificate is about to expire — like a passport with only a few days left. " +
    "Once it expires, browsers block your site with a scary warning. Renew it now so " +
    "visitors never see that screen."
  ),
  ssl_tls_version: (
    "Your site is using an old encryption method that has known weaknesses. Think of it " +
    "like using a cheap padlock from 2005 — hackers have had years to figure out how to " +
    "break it. Upgrade to TLS 1.2 or 1.3, the modern standard."
  ),

  // ── Security Headers ───────────────────────────────────────────────────────
  hdr_hsts: (
    "Your site doesn't force browsers to always use the secure version. An attacker on " +
    "the same Wi-Fi network can quietly intercept the connection before HTTPS kicks in. " +
    "HSTS closes that window by telling browsers to never even try the insecure version."
  ),
  hdr_csp: (
    "Your site has no rules about what scripts are allowed to run on it. A Content " +
    "Security Policy is like a guest list for a party — without one, anyone can walk in. " +
    "Attackers use this gap (called XSS) to inject malicious code into your pages."
  ),
  hdr_xfo: (
    "Your site can be secretly embedded inside another page in an invisible frame. Attackers " +
    "put your site behind a fake layer and trick visitors into clicking buttons they can't " +
    "see — this is called clickjacking. One header blocks it entirely."
  ),
  hdr_xcto: (
    "Browsers are allowed to guess what type of files your site serves. An attacker could " +
    "upload a disguised file (say, a text file that's actually a script) and trick the browser " +
    "into executing it. This header tells the browser to trust your file type labels and never guess."
  ),
  hdr_rp: (
    "When visitors click a link on your site and go somewhere else, their browser tells the " +
    "destination site where they came from. This can leak private URLs or session info. " +
    "A Referrer-Policy tells the browser how much (or how little) of that info to share."
  ),
  hdr_pp: (
    "Your site hasn't told browsers which device features — camera, microphone, location — " +
    "are off limits for third-party scripts. A Permissions-Policy locks those down so " +
    "an ad or tracking script can't quietly access them in the background."
  ),
  hdr_xxp: (
    "This is a basic, old-school header that tells older browsers to block obvious script " +
    "injection attacks. Modern browsers don't need it, but it's a quick win that protects " +
    "anyone still on an older browser."
  ),
  hdr_server_leak: (
    "Your server is advertising exactly what software it runs and which version — like wearing " +
    "a name tag that says 'I'm running Apache 2.4.49, which has a known critical bug.' " +
    "Hackers scan for this automatically. Just remove the header."
  ),
  hdr_powered_leak: (
    "Your site is broadcasting which programming language or framework it runs on. This gives " +
    "attackers a specific list of vulnerabilities to test against your site. Hiding this " +
    "doesn't fix anything, but it removes a free hint."
  ),
  hdr_aspnet_leak: (
    "Your site is revealing the exact version of Microsoft's ASP.NET framework it uses. " +
    "Combined with known vulnerability databases, attackers can immediately look up " +
    "exactly which exploits might work on your version."
  ),

  // ── Technology Detection ───────────────────────────────────────────────────
  tech_wordpress: (
    "Your site runs WordPress, which powers about 43% of the internet — making it by far " +
    "the most-attacked CMS. Outdated plugins are the #1 way WordPress sites get hacked. " +
    "Keep everything updated and remove plugins you don't use."
  ),
  tech_joomla: (
    "Your site runs Joomla, which has had a number of critical vulnerabilities over the years. " +
    "Every outdated extension is a potential entry point. Review and update everything regularly."
  ),
  tech_drupal: (
    "Your site runs Drupal, which had a severe class of vulnerabilities nicknamed 'Drupalgeddon' " +
    "that allowed full site takeovers without a login. Drupal is solid when kept current, " +
    "but falling behind on updates is dangerous."
  ),
  tech_asp_net: (
    "Your site is showing it uses Microsoft's ASP.NET framework. The version number being " +
    "visible means attackers can immediately narrow down which known exploits to try. " +
    "Suppressing the version header is a one-line config change."
  ),

  // ── File Exposure ──────────────────────────────────────────────────────────
  "file__git_HEAD": (
    "Your entire code history is publicly downloadable. Anyone can grab it — including " +
    "every password, API key, and secret you ever committed, even ones you deleted later. " +
    "This is one of the most serious exposures possible. Block access immediately."
  ),
  "file__git_config": (
    "Your Git config file is publicly readable. It can reveal your internal repo structure, " +
    "remote URLs, and developer usernames. Block it in your server config."
  ),
  "file__env": (
    "Your .env file is exposed to the public internet. This file is where developers store " +
    "database passwords, payment API keys, email credentials, and other secrets. " +
    "Treat this as a critical incident — rotate every secret in that file right now."
  ),
  "file__env_local": (
    "A local environment secrets file is publicly accessible. It likely contains sensitive " +
    "credentials meant only for your development machine. Block it and rotate any secrets it contains."
  ),
  "file__env_production": (
    "Your production secrets file is publicly accessible — this is extremely serious. " +
    "It likely contains live database passwords, payment processor keys, and other " +
    "credentials. Rotate everything in it immediately and block access to the file."
  ),
  "file_wp-config_php_bak": (
    "A backup of your WordPress config file is publicly accessible. It contains your " +
    "database name, username, and password in plain text. Change your database credentials now."
  ),
  "file_config_php_bak": (
    "A backup config file is publicly accessible and likely contains database credentials " +
    "or other sensitive settings. Delete or block the file and rotate any exposed secrets."
  ),
  "file_backup_zip": (
    "A backup archive of your site is publicly downloadable. This could contain your entire " +
    "codebase, database, and any secrets stored in files."
  ),
  "file_backup_tar_gz": (
    "A compressed backup of your site is publicly accessible. Treat this the same as " +
    "handing someone a full copy of your server."
  ),
  "file_database_sql": (
    "A full database dump is publicly downloadable. This means all your data — user accounts, " +
    "passwords, orders, messages — is sitting in a file anyone can grab. Take this offline immediately."
  ),
  "file_db_sql": (
    "A database dump file is publicly accessible. All your stored data is exposed."
  ),
  "file_phpinfo_php": (
    "A page that dumps your entire PHP and server configuration is publicly accessible. " +
    "It tells attackers exactly what versions of everything you run, what modules are loaded, " +
    "and even some server paths. Delete this file — it's never needed in production."
  ),
  "file_server-status": (
    "Apache's built-in status page is publicly accessible. It shows live information about " +
    "your server — active connections, request paths, and more. Restrict it to localhost only."
  ),
  "file_elmah_axd": (
    "Your ASP.NET application's error log is publicly readable. Error logs often contain " +
    "database connection strings, stack traces, and internal file paths — a roadmap for attackers."
  ),
  "file_trace_axd": (
    "ASP.NET's trace handler is enabled and public. It can expose request data, session info, " +
    "and application internals. Disable it in your web.config."
  ),
  "file__htaccess": (
    "Your Apache configuration file is publicly readable. It can reveal URL rewrite rules, " +
    "protected directory names, and other server internals."
  ),

  // ── DNS ────────────────────────────────────────────────────────────────────
  dns_resolves: (
    "Your domain name isn't resolving to an IP address — it's like a phone number that " +
    "doesn't connect to anything. Either your DNS records are missing or misconfigured."
  ),
  dns_spf: (
    "Without an SPF record, anyone on the internet can send emails that look like they came " +
    "from your domain. Scammers and phishers use this to impersonate businesses. An SPF record " +
    "is a public list of servers that are allowed to send on your behalf."
  ),
  dns_dmarc: (
    "DMARC tells email providers what to do when someone tries to fake an email from your domain — " +
    "reject it, quarantine it, or let it through. Without it, phishing emails using your name " +
    "go straight to inboxes with no warning."
  ),
  dns_caa: (
    "A CAA record is a lock on who can issue SSL certificates for your domain. Without one, " +
    "any of the hundreds of certificate authorities in the world could be tricked or compromised " +
    "into issuing a fake certificate for your site."
  ),
}

/**
 * Look up a plain-English explanation for a check_id.
 * Falls back to the original technical detail if no translation exists.
 */
export function noobify(checkId, technicalDetail) {
  return NOOBIFY_MAP[checkId] || null
}
