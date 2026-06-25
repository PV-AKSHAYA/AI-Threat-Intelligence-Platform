# 🛡️ AI Threat Intelligence Platform

An AI-powered cybersecurity intelligence platform built for the **SISA AI-Prism Hackathon 2026**.

The platform ingests threat intelligence reports, extracts Indicators of Compromise (IOCs), enriches them with contextual information, maps threats to the MITRE ATT&CK framework, calculates explainable risk scores, generates AI-powered threat intelligence reports, and produces SOC-ready Sigma detection rules.

---

# 🚀 Features

## Multi-Input Threat Analysis

- Analyze raw threat reports
- Upload PDF, DOCX, TXT, CSV, and JSON files
- Analyze CVE IDs
- Extract URLs, Domains, IP Addresses and Hashes

---

## IOC Extraction

Automatically extracts:

- IPv4 Addresses
- Domains
- URLs
- Email Addresses
- MD5
- SHA1
- SHA256
- CVE IDs

---

## Threat Enrichment

Provides:

- CVSS Score
- Severity
- Exploit Availability
- Malware Family
- Threat Actor
- Reputation Score

---

## MITRE ATT&CK Mapping

Automatically maps extracted threats to:

- Initial Access
- Execution
- Persistence
- Credential Access
- Privilege Escalation
- Exfiltration
- Impact

Includes an interactive MITRE ATT&CK chain visualization.

---

## Risk Scoring

Explainable risk scoring (0–100)

Risk Levels

- 🟢 Low
- 🟡 Medium
- 🟠 High
- 🔴 Critical

Displays contributing factors such as:

- CVSS
- IOC Reputation
- Exploit Availability
- Malware Association
- Threat Actor

---

## AI Threat Intelligence Report

Generates:

- Threat Summary
- Attack Scenario
- Business Impact
- Immediate Actions
- Long-Term Remediation
- Monitoring Recommendations

Powered by Google Gemini with Groq fallback.

---

## Detection Rules

Automatically generates:

- Sigma Rules

Supports one-click copy to clipboard.

---

## IOC Relationship Graph

Visualizes relationships between:

- Threat Actors
- Domains
- IP Addresses
- CVEs
- Malware Families

---

## Attack Path Prediction

Predicts the likely attacker kill chain based on the analyzed threat.

---

## Analysis History

Stores previous analyses using SQLite.

---

# 🛠 Tech Stack

## Frontend

- React
- Vite
- React Router
- Axios
- Recharts
- React Flow
- HTML
- CSS

## Backend

- FastAPI
- Python
- SQLAlchemy
- SQLite
- Pydantic

## AI

- Google Gemini API
- Groq API

---

# 📂 Project Structure

```
AI-Threat-Intelligence-Platform
│
├── backend
│   ├── app
│   │   ├── api
│   │   ├── models
│   │   ├── schemas
│   │   ├── services
│   │   └── utils
│   │
│   ├── seed_data
│   ├── tests
│   ├── requirements.txt
│   └── runtime.txt
│
├── frontend
│   ├── src
│   │   ├── components
│   │   ├── pages
│   │   ├── services
│   │   └── utils
│   │
│   ├── public
│   ├── package.json
│   └── vite.config.js
│
└── README.md
```

---

# ⚙️ Installation

## Backend

```bash
cd backend

python -m venv venv

source venv/bin/activate
```

Windows

```bash
venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create a `.env`

```text
GEMINI_API_KEY=your_key

GROQ_API_KEY=your_key
```

Run

```bash
uvicorn app.main:app --reload
```

---

## Frontend

```bash
cd frontend

npm install

npm run dev
```

---

# 📡 API Endpoints

## Analyze Threat

```
POST /api/analyze-threat
```

---

## Upload Threat Report

```
POST /api/analyze-threat/upload
```

---

## Analysis History

```
GET /api/analyses
```

---

## Analysis Details

```
GET /api/analyses/{analysis_id}
```

---

## Health Check

```
GET /health
```

---

# 📸 Screenshots

<img width="1129" height="670" alt="image" src="https://github.com/user-attachments/assets/8da0fac7-6dda-4d6b-97ce-c32c1369fb93" />
<img width="971" height="590" alt="image" src="https://github.com/user-attachments/assets/e1cfd09f-a349-444b-9cac-6887ffd0642c" />
<img width="1153" height="604" alt="image" src="https://github.com/user-attachments/assets/e19e2765-cd09-43b6-8d6d-6431deb50ed8" />




---

# 🎯 Demo Workflow

1. Paste a threat report or upload a file.
2. Extract Indicators of Compromise.
3. Perform Threat Enrichment.
4. Calculate Risk Score.
5. Generate MITRE ATT&CK Mapping.
6. View IOC Relationship Graph.
7. Predict Attack Path.
8. Generate AI Intelligence Report.
9. Export PDF/JSON.
10. Copy Sigma Rules.

---

# 🔮 Future Improvements

- YARA Rule Generation
- Splunk Query Generation
- Microsoft Sentinel KQL
- Elastic Queries
- Real-time Threat Feed Integration
- User Authentication
- Dark/Light Theme
- Dashboard Analytics

---

# 👨‍💻 Developer

**P.V. Akshaya**



---

# 📄 License

This project was developed for educational and hackathon purposes.
