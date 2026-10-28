# Sentinel TLS Security Analyzer

A Python and Streamlit-based cybersecurity project that analyzes HTTPS/TLS certificates and reports certificate validity, expiry risks, negotiated TLS configuration, and security findings.

## Features

- TLS certificate inspection
- Educational security score
- Certificate expiry warnings
- TLS protocol compatibility checks
- Security findings and recommendations
- SQLite scan history and comparison
- PDF and JSON security reports

## Technologies Used

- Python
- Streamlit
- SQLite
- SSL/TLS
- ReportLab

## Installation

1. Clone or download this repository.
2. Open the project folder in VS Code.
3. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Start the application:

   ```bash
   python -m streamlit run app.py
   ```

5. Open the local URL displayed in the terminal, usually http://localhost:8501.

## Disclaimer

This is an educational cybersecurity project. Its security score is a heuristic, not an industry-standard rating. A successful TLS connection does not guarantee that an entire website is secure.
