# AI-Driven SOC Triage & Big Data Log Reduction Pipeline

An automated Security Operations Center (SOC) Tier-1/Tier-2 triage pipeline that ingests high-volume raw HTTP/network telemetry, reduces log noise by **99.99%** using **DuckDB** vectorized SQL analytics, and leverages **Google Gemini** with **Pydantic** structured schemas to produce actionable **MITRE ATT&CK** incident reports.

## Architecture

```text
[Raw Security Telemetry]       [OLAP Aggregation Engine]        [LLM Threat Analyst]
  50,000+ JSONL Events   --->    DuckDB Vectorized SQL    --->   Gemini + Pydantic JSON
   (Normal + Attack)            (99.99% Noise Reduction)         (MITRE ATT&CK Triage)
                                           |                               |
                                           v                               v
                               suspicious_profiles.json            triage_report.json
```

## Key Engineering Highlights

- **Big Data Noise Reduction (DuckDB):** Processes 50,000 raw JSONL security events locally in **0.37s** using columnar OLAP queries, isolating 4 high-risk IP profiles with aggregated behavioral metrics (request velocity, HTTP error ratios, payload volume, user-agent anomalies, and sampled endpoints).
- **Deterministic Structured AI Outputs:** Enforces strict JSON schema validation via **Pydantic** (`ThreatAssessment`), eliminating hallucinated fields and guaranteeing machine-readable incident reports ready for SOAR/SIEM ingestion.
- **API Resilience & Model Fallback:** Implements timeout-guarded execution and automatic fallback across Gemini Flash models (`gemini-3.1-flash-lite`, `gemini-3.5-flash`, `gemini-3.8-flash`) to handle transient rate limits (`429`) and service spikes (`503`).
- **Automated MITRE ATT&CK Mapping:** Classifies multi-vector threats including Credential Brute-Force (`T1110`), Vulnerability/Directory Scanning (`T1595.002`), SQL Injection (`T1190`), and Automated Data Exfiltration (`T1537`).

## Project Structure

```text
ai-soc-triage-pipeline/
├── data/
│   ├── suspicious_profiles.json   # Aggregated behavioral profiles output by DuckDB
│   └── triage_report.json         # Final AI-generated SOC incident report
├── src/
│   ├── generate_logs.py           # Synthetic telemetry generator (benign + 4 attack patterns)
│   ├── bigdata_aggregator.py      # DuckDB OLAP log reduction & anomaly filtering
│   └── ai_triage_agent.py         # Resilient Gemini + Pydantic SOC triage agent
├── main.py                        # Unified end-to-end pipeline runner
├── requirements.txt               # Python dependencies
├── .env.example                   # Environment variable template
└── .gitignore                     # Secret and raw data exclusion rules
```

## Quickstart

1. **Clone the repository and create a virtual environment:**
   ```bash
   git clone [https://github.com/TrofinIonut/ai-soc-triage-pipeline.git](https://github.com/TrofinIonut/ai-soc-triage-pipeline.git)
   cd ai-soc-triage-pipeline
   python -m venv .venv
   # Windows:
   .\.venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure your API key:**
   ```bash
   cp .env.example .env
   # Add your GEMINI_API_KEY inside .env
   ```

4. **Run the full pipeline:**
   ```bash
   python main.py
   ```

## Sample SOC Triage Output (`data/triage_report.json`)

```json
{
  "source_ip": "45.133.1.99",
  "telemetry_summary": {
    "total_requests": 180,
    "requests_per_minute": 45.0,
    "total_mb_transferred": 0.09,
    "user_agents": ["sqlmap/1.7.11#stable"]
  },
  "ai_triage": {
    "attack_classification": "SQL Injection",
    "severity": "CRITICAL",
    "mitre_attack_technique": "T1190 - Exploit Public-Facing Application",
    "confidence_score": 100,
    "technical_summary": "The source IP is actively performing automated SQL injection attacks using the sqlmap tool. The payloads target database structure and authentication bypass, evidenced by the presence of DROP TABLE, UNION SELECT, and time-based blind SQLi patterns in the request parameters.",
    "recommended_remediation": [
      "Immediately block source IP 45.133.1.99 at the WAF/perimeter firewall.",
      "Audit database query logs for unauthorized read/write execution during the attack window.",
      "Enforce parameterized queries/prepared statements on all affected API endpoints."
    ]
  }
}
```
