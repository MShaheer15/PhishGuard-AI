# 🛡️ PhishGuard AI

> **AI-powered phishing URL detection** using machine learning, SSL/TLS analysis, and real-time security scoring.

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-teal.svg)](https://fastapi.tiangolo.com/)

---

## Overview

PhishGuard AI is a full-stack phishing detection system that combines **machine learning** with **real-time security analysis** to determine whether a URL is legitimate or a phishing attempt. It extracts 50+ features from URLs, validates SSL/TLS certificates, checks security headers, and applies intelligent score adjustments to deliver accurate threat assessments.

### Key Features

- **ML-Based Detection** — Random Forest classifier trained on 10,000+ URLs with 96%+ accuracy
- **SSL/TLS Validation** — Real-time certificate checking (expiry, self-signed, domain mismatch, TLS version)
- **Website Existence Check** — DNS resolution + HTTP reachability verification before analysis
- **Security Headers Analysis** — HSTS, CSP, X-Frame-Options, mixed content detection
- **Score Adjustment Engine** — Penalty/bonus system that refines ML scores using security signals
- **Smart Whitelist** — 700+ known-safe domains with subdomain-aware matching
- **Dashboard** — Dark-themed UI with scan history, threat intelligence stats, and detailed reports
- **REST API** — FastAPI backend with OpenAPI docs at `/docs`

---

## Project Structure

```
PhishGuard-AI/
├── backend/
│   ├── app.py                 # FastAPI application & API endpoints
│   ├── feature_extractor.py   # 50+ URL feature extraction engine
│   ├── ssl_checker.py         # SSL/TLS certificate & security analysis
│   ├── score_adjuster.py      # ML score adjustment (penalties/bonuses)
│   ├── url_checker.py         # Website existence checker (DNS + HTTP)
│   ├── whitelist.py           # Known-safe domain whitelist
│   ├── database.py            # SQLAlchemy models & database config
│   └── train_model.py         # Model training script with GridSearchCV
├── frontend/
│   ├── index.html             # Single-page dashboard application
│   └── styles.css             # Dark theme with glassmorphism design
├── ml/
│   ├── phishing_model.pkl     # Trained Random Forest model
│   └── features.json          # Feature names used by the model
├── dataset/
│   └── Phishing_Legitimate_full.csv  # Training dataset (10,000+ URLs)
├── test_api.py                # API integration tests
├── .env                       # Environment variables (not in repo)
├── .gitignore
├── LICENSE
├── README.md
└── DOCUMENTATION.md
```

---

## Getting Started

### Prerequisites

- **Python 3.10+**
- **PostgreSQL** (or update `DATABASE_URL` for SQLite)
- **pip** package manager

### 1. Clone the Repository

```bash
git clone https://github.com/WisalAhmadd/PhishGuard-AI.git
cd PhishGuard-AI
```

### 2. Install Dependencies

```bash
pip install fastapi uvicorn sqlalchemy psycopg2-binary python-dotenv pandas scikit-learn requests beautifulsoup4 tldextract pydantic
```

### 3. Configure Environment

Create a `.env` file in the project root:

```env
DATABASE_URL=postgresql://postgres:yourpassword@localhost:5432/phishing_db
```

> **Note:** For quick testing without PostgreSQL, you can use SQLite by setting:
> `DATABASE_URL=sqlite:///./phishguard.db`

### 4. Set Up Database

The database tables are created automatically when the server starts.

### 5. Run the Backend

```bash
cd backend
python app.py
```

The API will be available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### 6. Open the Frontend

Open `frontend/index.html` in your browser, or serve it with any static file server:

```bash
cd frontend
python -m http.server 5500
```

Then navigate to `http://localhost:5500`.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Full phishing analysis (ML + SSL + existence check) |
| `POST` | `/check-exists` | Standalone website existence check (DNS + HTTP) |
| `GET` | `/history` | Get scan history (last 50 results) |
| `GET` | `/stats` | Get aggregate statistics |

### Example: Scan a URL

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

**Response:**
```json
{
  "url": "https://www.google.com",
  "is_phishing": false,
  "confidence": 0.02,
  "whitelisted": true,
  "website_exists": true,
  "existence_details": {
    "dns_resolves": true,
    "is_reachable": true,
    "status_code": 200,
    "response_time_ms": 450.2,
    "ip_address": "142.250.80.46"
  },
  "features": { ... },
  "security_details": { ... }
}
```

### Example: Check Website Existence

```bash
curl -X POST http://localhost:8000/check-exists \
  -H "Content-Type: application/json" \
  -d '{"url": "https://fakexyz99999.com"}'
```

**Response:**
```json
{
  "url": "https://fakexyz99999.com",
  "exists": false,
  "dns_resolves": false,
  "is_reachable": false,
  "status_code": 0,
  "response_time_ms": -1,
  "ip_address": null,
  "error": "DNS resolution failed — domain \"fakexyz99999.com\" does not exist"
}
```

---

## How It Works

```
URL Input
    │
    ▼
┌──────────────────┐
│ Website Existence │ ── DNS fails ──► Return early (not found)
│ Check (DNS+HTTP) │
└──────────────────┘
    │ exists
    ▼
┌──────────────────┐
│ Whitelist Check   │ ── match ──► Safe (bypass ML)
└──────────────────┘
    │ not whitelisted
    ▼
┌──────────────────┐    ┌─────────────────────┐
│ Feature Extraction│───►│ ML Model Prediction │
│ (50+ features)   │    │ (Random Forest)     │
└──────────────────┘    └─────────────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Score Adjustment │
                     │ (SSL/TLS +      │
                     │  Security Hdrs) │
                     └─────────────────┘
                              │
                              ▼
                     Final Verdict + Confidence
```

### Feature Categories

| Category | Features |
|----------|----------|
| **URL Structure** | Length, dots, dashes, subdomains, path depth, query params |
| **Suspicious Patterns** | IP address, random strings, embedded brand names, `@` symbol |
| **Page Content** | Forms, iframes, external links, sensitive words, right-click disabled |
| **SSL/TLS** | Certificate validity, self-signed, expiry, domain match, TLS version |
| **Security Headers** | HSTS, CSP, X-Frame-Options, mixed content |

---

## Training the Model

To retrain the model with updated data:

```bash
cd backend
python train_model.py
```

This will:
1. Load the dataset from `dataset/Phishing_Legitimate_full.csv`
2. Run hyperparameter tuning with GridSearchCV
3. Perform 5-fold cross-validation
4. Save the model to `ml/phishing_model.pkl`
5. Save feature names to `ml/features.json`

---

## Running Tests

```bash
# Start the backend first, then:
python test_api.py
```
Tests cover: safe URL scan, suspicious URL scan, HTTPS site scan, history endpoint, and stats endpoint.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python, FastAPI, Uvicorn |
| **ML** | scikit-learn (Random Forest), pandas, NumPy |
| **Database** | PostgreSQL / SQLite via SQLAlchemy |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **Security** | Python `ssl` stdlib, `requests`, `tldextract` |

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Author
**Wisal Ahmad** — [GitHub](https://github.com/WisalAhmadd)
