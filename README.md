# Phishing Email Detector

![CI Status](https://github.com/mateuszpoborski48-cell/phishing-email-detector/actions/workflows/ci.yml/badge.svg)

A web-based cybersecurity application designed to analyse email messages and identify potential phishing threats.

The application examines email content, sender information, authentication headers, URLs and attachments to calculate a phishing risk score and explain suspicious indicators.

## Features

- **Email scanning:** Analyse pasted email text or uploaded `.eml` files.
- **Phishing detection:** Identify suspicious language and common phishing indicators.
- **Sender analysis:** Detect potentially impersonated brands and suspicious sender domains.
- **Email header analysis:** Examine SPF, DKIM and DMARC authentication results.
- **URL analysis:** Identify suspicious links, shortened URLs and lookalike domains.
- **Attachment analysis:** Check attachment filenames and potentially dangerous extensions.
- **Risk scoring:** Assign a phishing risk score from 0 to 100.
- **Security dashboard:** Display scan statistics and risk distribution.
- **Database Explorer:** Browse, search, filter and sort saved phishing scan records.
- **Scan explanations:** Explain detected warnings and provide recommendations.

## Technologies Used

| Component | Technology |
|---|---|
| Frontend | React, Vite, JavaScript, CSS |
| Backend | Python, FastAPI |
| Database | SQLite |
| Automated testing | pytest |
| Continuous Integration | GitHub Actions |
| Code quality | ESLint |
| Static security analysis | Bandit |
| Dependency security | pip-audit, npm audit |
| Version control | Git and GitHub |

## Installation and Setup

### Backend

Navigate to the backend directory:

```bash
cd backend
```

Create a Python virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI backend:

```bash
uvicorn main:app --reload
```

The backend runs at `http://127.0.0.1:8000`.

### Frontend

Open a separate terminal and navigate to the frontend directory:

```bash
cd frontend
```

Install dependencies:

```bash
npm ci
```

Start the React development server:

```bash
npm run dev
```

Open the local address displayed by Vite in your browser.

## How the Application Works

1. The user pastes an email or uploads an `.eml` file.
2. The React frontend sends the email to the FastAPI backend.
3. The backend analyses the message using several detection modules.
4. The application calculates a risk score and assigns a risk level.
5. The user receives detected warnings, explanations and recommendations.
6. Scan information is saved in SQLite for future analysis.
7. The dashboard and Database Explorer allow users to review previous scans.

## Continuous Integration

The project uses GitHub Actions to automatically check code changes whenever a push or pull request occurs.

The workflow is defined in `.github/workflows/ci.yml`.

### Automated CI Checks

| Check | Tool | Purpose |
|---|---|---|
| Backend testing | pytest | Verify Python application functionality |
| Frontend build | Vite | Verify the React application builds |
| Code quality | ESLint | Detect frontend code-quality issues |
| Python security scanning | Bandit | Identify potential security weaknesses |
| Python dependency audit | pip-audit | Detect known vulnerabilities in Python dependencies |
| JavaScript dependency audit | npm audit | Detect known vulnerabilities in frontend dependencies |

These six checks are organised into four GitHub Actions jobs.

A failed check causes its associated CI job to fail, helping developers identify problems before further development or deployment.

### Running Checks Locally

From the backend directory:

```bash
python -m pytest -v
```

From the frontend directory:

```bash
npm run lint
npm run build
npm audit
```

Python dependency audit, from the project root:

```bash
python -m pip_audit -r backend/requirements.txt
```

## Project Limitations

The application uses rule-based phishing indicators and risk scoring. Its results should be treated as security guidance rather than definitive proof that an email is safe or malicious.

Future improvements may include additional automated tests, enhanced detection accuracy, machine learning integration and deployment.

## Project Status

The application currently supports email analysis, risk scoring, scan history, a security dashboard and database exploration.

A GitHub Actions CI pipeline has been implemented successfully, with backend testing, frontend building, linting, static security analysis and dependency auditing.

## Author

Mateusz Poborski

Information Technology and Cybersecurity Project

Munster Technological University (MTU)