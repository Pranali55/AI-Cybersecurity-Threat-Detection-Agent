# AI Cybersecurity Threat Detection Agent

A defensive cybersecurity portfolio project that analyses uploaded authentication logs, detects suspicious patterns with transparent rules, assigns risk scores, and generates investigation summaries.

## Features
- Upload UTF-8 `.log`, `.txt`, or `.csv` files (up to 5 MB).
- Parse common SSH authentication logs or a simple CSV schema.
- Detect repeated failed logins and successful logins after repeated failures.
- Generate explainable severity and risk scores.
- View findings in a local web dashboard and generate a Markdown report.
- Includes sample data and a basic automated test.

## Stack
Python, FastAPI, HTML/CSS/JavaScript, pytest. The modular structure is ready for future Pandas, ML, LLM, and LangGraph extensions.

## Windows setup
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000. API docs: http://127.0.0.1:8000/docs

Upload `sample_logs/auth.log` or `sample_logs/auth.csv`.

CSV schema: `timestamp,source_ip,event,user,status`

## Tests
```powershell
pytest
```

## Safety and limitations
For defensive analysis of logs you are authorised to inspect. This project does not scan networks, exploit systems, block IP addresses, modify accounts, or execute incident-response actions. Alerts are heuristic indicators, not proof of compromise. Correlate findings with additional telemetry and follow your organisation's incident-response process.

This starter version uses deterministic rules. LLM explanations, ML anomaly detection, LangGraph orchestration, authentication, persistent storage, Docker, and cloud deployment are planned enhancements, not claimed as implemented features.

## Author
Pranali Koli
