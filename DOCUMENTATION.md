# PhishGuard AI — Technical Documentation

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Backend Modules](#backend-modules)
3. [API Reference](#api-reference)
4. [Feature Extraction](#feature-extraction)
5. [ML Model](#ml-model)
6. [Score Adjustment Engine](#score-adjustment-engine)
7. [Website Existence Checker](#website-existence-checker)
8. [SSL/TLS Security Checker](#ssltls-security-checker)
9. [Whitelist System](#whitelist-system)
10. [Database Schema](#database-schema)
11. [Frontend Architecture](#frontend-architecture)
12. [Configuration](#configuration)

---

## Architecture Overview

PhishGuard AI follows a layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (HTML/CSS/JS)                │
│              index.html + styles.css                    │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP (REST API)
┌──────────────────────▼──────────────────────────────────┐
│                  FastAPI Application                     │
│                     app.py                               │
├──────────┬───────────┬────────────┬─────────────────────┤
│ URL      │ Feature   │ Score      │ Database             │
│ Checker  │ Extractor │ Adjuster   │ (SQLAlchemy)         │
├──────────┼───────────┼────────────┤                     │
│ SSL      │ Whitelist │ ML Model   │                     │
│ Checker  │           │ (.pkl)     │                     │
└──────────┴───────────┴────────────┴─────────────────────┘
```

**Request Flow:**
1. URL submitted via API → Website existence check (DNS + HTTP)
2. If website exists → Whitelist check → Feature extraction (50+ features)
3. ML model prediction → Score adjustment (SSL/security signals)
4. Response with verdict, confidence, features, and security details
5. Result saved to database

---

## Backend Modules

### `app.py` — API Application

The main FastAPI application. Handles:
- Model loading (pickle) and feature configuration (JSON)
- CORS middleware configuration
- Request validation via Pydantic models
- Database session management via dependency injection
- Route handlers for all API endpoints

### `feature_extractor.py` — Feature Extraction

Extracts 50+ features from a URL across these categories:
- **URL structure** — length, dots, dashes, subdomains, path depth, query params
- **Suspicious patterns** — IP address usage, random strings (Shannon entropy), embedded brand names
- **Page content** — forms, iframes, external links, sensitive words, status bar manipulation
- **SSL/TLS signals** — certificate validity, self-signed, expiry, TLS version
- **Security headers** — HSTS, CSP, X-Frame-Options, mixed content

### `ssl_checker.py` — SSL/TLS Analysis

Performs real-time SSL/TLS certificate validation:
- Certificate retrieval with and without verification
- Issuer, subject, expiry, and self-signed detection
- Domain match with wildcard support (`*.example.com`)
- TLS version detection and encoding
- Security headers analysis
- HTTP-to-HTTPS redirect detection
- Mixed content scanning

### `score_adjuster.py` — Score Adjustment

Refines raw ML prediction scores using security signals:
- **Penalties** (increase phishing probability): no SSL, self-signed cert, expired cert, domain mismatch, no HSTS, mixed content, deprecated TLS, new cert on suspicious domain
- **Bonuses** (decrease phishing probability): valid SSL from trusted issuer, full security headers, TLS 1.3, HTTP→HTTPS redirect
- Final score = ML_score + penalties − bonuses, clamped to [0.0, 1.0]

### `url_checker.py` — Website Existence

Verifies whether a target URL is live before analysis:
- **DNS Resolution** — uses `socket.getaddrinfo()` to check domain existence
- **HTTP Reachability** — HEAD request with GET fallback
- **Response metrics** — status code, response time (ms), resolved IP
- Returns early if DNS fails to avoid unnecessary processing

### `whitelist.py` — Safe Domain List

Contains 700+ known-safe domains organized by category (search engines, social media, banking, government, etc.). Features subdomain-aware matching — `mail.google.com` is recognized as safe because `google.com` is whitelisted.

### `database.py` — Database Layer

SQLAlchemy ORM setup with:
- `ScanResult` model for storing scan history
- Session factory with dependency injection
- Auto-creation of tables on startup

### `train_model.py` — Model Training

Training pipeline:
1. Loads CSV dataset
2. Preprocessing (drop ID, fill NaN)
3. Train/test split (80/20)
4. GridSearchCV hyperparameter tuning
5. 5-fold cross-validation
6. Saves model (.pkl) and feature list (.json)

---

## API Reference

### `POST /scan`

Full phishing analysis of a URL.

**Request Body:**
```json
{ "url": "https://example.com" }
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | The scanned URL |
| `is_phishing` | boolean | Whether URL is classified as phishing |
| `confidence` | float | Adjusted phishing probability (0.0–1.0) |
| `whitelisted` | boolean | Whether domain is in the safe list |
| `website_exists` | boolean | Whether the website is online |
| `existence_details` | object | DNS/HTTP reachability details |
| `features` | object | All 50+ extracted feature values |
| `security_details` | object | SSL/TLS and security header analysis |

---

### `POST /check-exists`

Standalone website existence check (lightweight, no ML).

**Request Body:**
```json
{ "url": "https://example.com" }
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | The checked URL |
| `exists` | boolean | True if DNS resolves AND server responds |
| `dns_resolves` | boolean | True if domain resolves to an IP |
| `is_reachable` | boolean | True if HTTP request got a response |
| `status_code` | integer | HTTP status code (0 if unreachable) |
| `response_time_ms` | float | Round-trip time in ms (-1 if failed) |
| `ip_address` | string | Resolved IP address |
| `error` | string | Error message if check failed |

---

### `GET /history`

Returns the last 50 scan results, newest first.

**Response:** Array of `HistoryItem` objects.

---

### `GET /stats`

Returns aggregate scan statistics.

**Response:**
```json
{
  "total_scans": 150,
  "phishing_detected": 42,
  "safe_urls": 108,
  "whitelisted_count": 35
}
```

---

## Feature Extraction

### URL Structure Features (15)

| Feature | Description |
|---------|-------------|
| `UrlLength` | Total URL character length |
| `NumDots` | Number of dots in URL |
| `NumDash` / `NumDashInHostname` | Dash count (total / hostname only) |
| `AtSymbol` / `TildeSymbol` | Presence of `@` or `~` |
| `NumUnderscore` / `NumPercent` | Count of `_` and `%` |
| `NumQueryComponents` / `NumAmpersand` | Query parameter count |
| `NumHash` / `NumNumericChars` | Hash symbols / digits |
| `SubdomainLevel` / `PathLevel` | Depth of subdomain/path nesting |
| `HostnameLength` / `PathLength` / `QueryLength` | Component lengths |
| `DoubleSlashInPath` / `HttpsInHostname` | Suspicious patterns |
| `NoHttps` | 1 if URL uses HTTP instead of HTTPS |
| `IpAddress` | 1 if hostname is a raw IP address |

### Suspicious Pattern Features (4)

| Feature | Description |
|---------|-------------|
| `RandomString` | Shannon entropy + consonant ratio analysis |
| `EmbeddedBrandName` | Known brand name in URL but not the actual domain |
| `DomainInSubdomains` | Brand name in subdomain (e.g., `google.evil.com`) |
| `DomainInPaths` | Brand name in URL path |

### Page Content Features (14)

| Feature | Description |
|---------|-------------|
| `MissingTitle` | Page has no `<title>` tag |
| `InsecureForms` / `RelativeFormAction` / `ExtFormAction` / `AbnormalFormAction` | Form action analysis |
| `SubmitInfoToEmail` | Form action uses `mailto:` |
| `IframeOrFrame` | Presence of iframe/frame elements |
| `PctExtHyperlinks` / `PctNullSelfRedirectHyperlinks` | Link analysis ratios |
| `PctExtResourceUrls` / `ExtFavicon` | External resource ratios |
| `RightClickDisabled` / `PopUpWindow` / `FakeLinkInStatusBar` | JavaScript manipulation |
| `FrequentDomainNameMismatch` | >50% of links go to different domains |
| `ImagesOnlyInForm` | Forms containing only images (no inputs) |
| `NumSensitiveWords` | Count of phishing-related keywords |

### SSL/TLS Features (13)

| Feature | Description |
|---------|-------------|
| `SSLValid` | Certificate passes validation |
| `SSLSelfSigned` / `SSLExpired` / `SSLExpiringSoon` | Certificate issues |
| `SSLDomainMismatch` | Cert domain ≠ hostname |
| `SSLCertAgeDays` | Certificate age in days |
| `TLSVersion` | Encoded TLS version (1.3→3, 1.2→2, etc.) |
| `HasHSTS` / `HasCSP` / `HasXFrameOptions` | Security header presence |
| `HttpToHttpsRedirect` | HTTP redirects to HTTPS |
| `MixedContent` | HTTPS page loads HTTP resources |
| `SecurityHeadersScore` | Sum of security headers present (0–5) |

---

## ML Model

- **Algorithm:** Random Forest Classifier
- **Dataset:** 10,000+ URLs (phishing + legitimate), 50+ features
- **Training:** GridSearchCV with 3-fold CV for hyperparameter tuning
- **Validation:** 5-fold cross-validation on training set
- **Output:** Probability distribution [P(legitimate), P(phishing)]
- **Threshold:** Phishing if adjusted_score > 0.5

---

## Score Adjustment Engine

### Penalties (Increase Phishing Score)

| Rule | Weight | Trigger |
|------|--------|---------|
| No SSL | +15% | No SSL certificate detected |
| Self-Signed | +12% | Self-signed certificate |
| Domain Mismatch | +15% | Cert domain ≠ hostname |
| Expired Cert | +10% | SSL certificate expired |
| Deprecated TLS | +8% | TLS ≤ 1.1 |
| Mixed Content | +5% | HTTPS page loads HTTP resources |
| New Cert + Suspicious | +5% | Cert < 30 days old AND ML score > 0.3 |
| No HSTS | +3% | Missing HSTS header |
| Expiring Soon | +3% | Cert expires within 30 days |

### Bonuses (Decrease Phishing Score)

| Rule | Weight | Trigger |
|------|--------|---------|
| Valid SSL (Trusted) | −5% | Valid cert from trusted CA |
| Full Security Headers | −5% | HSTS + CSP + X-Frame-Options all present |
| TLS 1.3 | −2% | Latest TLS protocol |
| HTTP→HTTPS Redirect | −2% | HTTP redirects to HTTPS |

---

## Website Existence Checker

Performs a two-step verification before running the full analysis:

1. **DNS Resolution** — `socket.getaddrinfo()` with 5s timeout
2. **HTTP Reachability** — HEAD request (fallback to GET) with 8s timeout

**Three possible states:**
- ✅ **Online** — DNS resolves AND server responds with HTTP status
- ⚠️ **Unreachable** — DNS resolves but server doesn't respond
- ❌ **Not Found** — DNS resolution fails (domain doesn't exist)

If DNS fails, the `/scan` endpoint returns early with `website_exists: false` and skips the expensive feature extraction pipeline.

---

## Database Schema

### `scan_results` Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | Integer (PK) | Auto-incrementing ID |
| `url` | String (indexed) | Scanned URL |
| `is_phishing` | Boolean | Phishing verdict |
| `confidence` | Float | Adjusted confidence score |
| `whitelisted` | Boolean | Whether domain was whitelisted |
| `timestamp` | DateTime | Scan timestamp (UTC) |
| `features` | String (JSON) | Extracted features |
| `security_details` | String (JSON) | SSL/security analysis |

---

## Frontend Architecture

Single-page application with four views:
- **Scanner** — URL input, scan results, existence status, feature breakdown, security analysis
- **History** — Table of past scans with verdict, confidence, and source
- **Intelligence** — Aggregate stats (total scans, phishing detected, safe, whitelisted)
- **Settings** — Dark/light theme toggle

The frontend communicates with the backend via `fetch()` to `http://localhost:8000`.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://postgres:admin@localhost:5432/phishing_db` | Database connection string |

### Supported Databases

- **PostgreSQL** (recommended) — `postgresql://user:pass@host:port/dbname`
- **SQLite** (for development) — `sqlite:///./phishguard.db`
