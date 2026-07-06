# Security

ReQuiem is a security tool, so its own posture matters. This document records
the controls in place and the results of the internal security assessment.

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security → Advisories) or
email the maintainer. Do not file public issues for exploitable bugs.

## Controls in place

### Authentication & sessions
- Passwords hashed with **scrypt** (memory-hard, per-user salt); never stored
  or logged in plaintext.
- **Login is constant-time w.r.t. account existence** — a scrypt hash runs even
  for unknown emails, defeating timing-based user enumeration.
- Sessions are **signed JWTs (HS256)** in an **HttpOnly** cookie (JS cannot read
  it → XSS cannot exfiltrate it).
- JWT verification **pins the algorithm** and **requires `exp`, `iat`, `nbf`,
  `sub`, `iss`** — rejecting `alg=none`, non-expiring, and issuer-spoofed tokens.
- Cookie flags adapt to the deployment: `Secure` + `SameSite=None` for
  cross-origin HTTPS, `SameSite=Lax` for same-origin.

### Per-user secrets
- Each user's API keys are **encrypted at rest** (Fernet / AES-128-CBC+HMAC)
  with a server key derived from `REQUIEM_SECRET`. A DB leak yields ciphertext.
- Ciphertext is **bound to `(user_id, key_name)`** — copying one row's ciphertext
  into another user/slot fails to decrypt, so even a DB-write compromise can't
  cross-decrypt keys.
- Key values are **write-only** over the API — you can set them and see which
  are set, but never read them back.

### Transport & browser hardening
- **CORS allowlist** (`REQUIEM_ALLOWED_ORIGINS`) for credentialed requests.
- **CSRF protection**: state-changing requests must be JSON (forces a CORS
  preflight) or carry `X-Requested-With` — an HTML `<form>` can do neither
  cross-origin.
- **Security headers on every response**: `Content-Security-Policy`
  (`script-src 'none'`, `default-src 'none'`, `frame-ancestors 'none'`),
  `Strict-Transport-Security`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
  `Permissions-Policy`.
- The self-contained HTML report carries **no inline scripts or event handlers**
  (CSP-clean).

### Input validation
- **Email**: strict pattern (`\A…\Z` anchors, not `^…$` — blocks the trailing-
  newline bypass), control-char rejection, length cap (254).
- Hash and API-key-value validators likewise use `\A…\Z` so a trailing newline
  cannot slip an injected character into an outbound request.
- Session `sub` claim must be strict digits (no `int()` whitespace coercion).
- **Password**: ≥10 chars, ≥3 character classes, length cap.
- **Hashes**: must be exactly MD5/SHA1/SHA256 hex before any external call —
  blocks SSRF/injection via the path segment.
- **API-key values**: charset-restricted, length-capped.
- **Filenames** in `Content-Disposition` are sanitized (no CR/LF/quotes/path
  separators → no header injection or traversal).
- **Body/upload size caps**: 32 MB samples, 8 MB report JSON.

### Rate limiting (per instance)
- Register: 5/hour/IP. Login: 10/5min/IP **and** 5/5min/email (credential
  stuffing). Hash lookup: 30/min. Investigate: 20/min. **Analysis endpoints
  (`/analyze`, `/analyze/html`, `/analyze/pdf`, `/report/pdf`): 20/min** — so
  anonymous callers can't exhaust CPU with the heavy pipeline.
- **X-Forwarded-For is not trusted by default.** The rate-limit key uses the
  direct peer IP unless `REQUIEM_TRUSTED_PROXIES=N` is set, in which case the
  client is read N hops from the right of XFF — an unforgeable position behind
  exactly N trusted proxies. This prevents rate-limit bypass via a spoofed XFF.
- The limiter's memory is **bounded** (100k keys, with stale-key eviction) so an
  attacker can't exhaust RAM by flooding the per-email bucket with unique
  addresses.

### Authorization & SSRF
- Per-user API keys are **always scoped to the session user id** — no
  user-supplied identifier, so there is no IDOR handle.
- URL-valued keys (`CAPE_URL`) are **SSRF-validated**: http(s) only, and the
  host must not resolve to a private/loopback/link-local/reserved address or a
  cloud-metadata endpoint (`169.254.169.254`, `metadata.google.internal`).
- All external-API hosts (VirusTotal/MalwareBazaar/Hybrid Analysis/Triage) are
  **hardcoded**; only a format-validated hash is interpolated into the path.

### Injection & memory safety
- All SQL is **parameterized** (no string building).
- **Parsers are fuzz-hardened**: 80+ malformed/random PE/ELF inputs (max section
  counts, huge size claims, truncated headers, pure garbage) produce zero
  crashes and zero slowdowns.
- Log messages strip CR/LF (no log-forging); no emails/passwords/keys/tokens are
  ever logged.
- The HTML report **escapes all binary-derived data** (mnemonics, operands,
  strings, IOCs, filenames) with `html.escape(quote=True)`.
- IOC/string extraction regexes are **linear** — no ReDoS on pathological input
  (validated: 5 MB adversarial input processes in < 0.3s).
- Errors return a generic message; **no stack traces or internals** leak to
  clients (global exception handler logs server-side only).
- **No ReDoS**: the IOC domain regex was rewritten to remove a nested quantifier
  that backtracked for 5s+ on adversarial input; it now matches in <200ms on the
  same 40k-char payload. All input regexes verified linear.

### Information disclosure
- Interactive **API docs (`/docs`, `/redoc`, `/openapi.json`) are disabled** by
  default (enable only in dev with `REQUIEM_ENABLE_DOCS=1`).
- The `/config` endpoint (which exposed the server's own key-configuration
  state) was **removed** from the web API.
- **Sessions are checked against the DB on every request** — deleting a user
  immediately invalidates their outstanding session cookie.
- `Content-Disposition` filenames are ASCII-sanitized against quote breakout,
  CRLF injection, path traversal, and RTL-override (`U+202E`) tricks.

### Safe by design
- Samples are **never executed locally** and **never redistributed/downloaded**.
- Dynamic behavior comes from a sandbox the operator controls, or an *existing*
  hosted cloud report (VirusTotal / Hybrid Analysis / Triage) — by hash only.

## Deployment hardening (production)

Set these on the API service:

```
REQUIEM_SECRET=<long random value>          # signs tokens, encrypts keys
REQUIEM_COOKIE_SECURE=1                       # HTTPS-only cookie
REQUIEM_COOKIE_SAMESITE=none                  # cross-origin frontend/api
REQUIEM_ALLOWED_ORIGINS=https://your-frontend # exact origin(s)
REQUIEM_DATA_DIR=/var/requiem-data            # persistent disk for the DB
```

The included `render.yaml` sets all of these.

## Resource & caching
- **PDF render concurrency is capped** (semaphore, default 2, via
  `REQUIEM_PDF_CONCURRENCY`) so a burst of report requests can't fork-bomb
  headless Chromium and exhaust host memory; a saturated pool returns the HTML
  fallback instead of queuing.
- **`Cache-Control: no-store` on all API responses** — per-user data is never
  cached by the browser or a shared proxy.

## Dependencies
- Audited with `pip-audit` and `npm audit`; vulnerable packages upgraded
  (`python-multipart`, `starlette`, `urllib3`, `requests`, `PyJWT`, Next.js).
  Secure version floors are pinned in `requirements.txt` / `pyproject.toml`.

## Known residual items

- **Rate limiting is per-instance (in-memory).** For multi-instance
  deployments, back it with Redis.
- **Next.js**: pinned to the latest patched 14.2.x. Two advisories remain that
  are only fully resolved in Next 15; both concern features ReQuiem does not use
  (image-optimizer remote patterns, insecure RSC/Server Actions), so they are
  not exploitable here.
- **JWTs are not individually revocable** before expiry (7-day TTL). Rotating
  `REQUIEM_SECRET` invalidates all sessions if needed.
