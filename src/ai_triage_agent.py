from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import json
import os
import time
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

load_dotenv()

INPUT_FILE = os.path.join("data", "suspicious_profiles.json")
OUTPUT_FILE = os.path.join("data", "triage_report.json")


class ThreatAssessment(BaseModel):
    attack_classification: str = Field(
        description="Tipul principal al atacului detectat (ex: Credential Brute-Force, SQL Injection, Directory Enumeration, Data Exfiltration)"
    )
    severity: str = Field(
        description="Nivelul de severitate: LOW, MEDIUM, HIGH sau CRITICAL"
    )
    mitre_attack_technique: str = Field(
        description="ID-ul si numele tehnicii MITRE ATT&CK relevante (ex: T1110 - Brute Force)"
    )
    confidence_score: int = Field(
        description="Scor de incredere intre 0 si 100 bazat pe telemetrie"
    )
    technical_summary: str = Field(
        description="Explicatie tehnica concisa (2-3 fraze) despre comportamentul IP-ului si indicatorii de compromitere (IoC)"
    )
    recommended_remediation: list[str] = Field(
        description="Lista cu 2-3 actiuni concrete de izolare si remediere pentru echipa SOC"
    )


SYSTEM_PROMPT = """
You are a Senior SOC Threat Analyst performing automated Tier-1/Tier-2 alert triage.
You receive aggregated network and HTTP telemetry metrics for suspicious source IPs extracted from a Big Data log pipeline.
Analyze the request rate, HTTP status code distribution, user agents, and sampled endpoints objectively.
Map the behavior accurately to the MITRE ATT&CK framework and provide actionable containment steps.
Do not invent telemetry data that is not present in the input JSON.
"""


def get_prioritized_models(client: genai.Client) -> list[str]:
    preferred_order = ["gemini-3.1-flash-lite", "gemini-3.5-flash", "gemini-3.8-flash"]
    available = []
    try:
        for m in client.models.list():
            name = m.name.replace("models/", "")
            if "flash" in name and "2.5" not in name and "tts" not in name and "image" not in name:
                available.append(name)
    except Exception:
        return preferred_order

    ordered = [m for m in preferred_order if m in available]
    for m in available:
        if m not in ordered:
            ordered.append(m)
    return ordered[:3] if ordered else preferred_order


def call_gemini_with_timeout(client: genai.Client, model_name: str, prompt: str, timeout_sec: int = 25) -> dict:
    def _api_call():
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                response_mime_type="application/json",
                response_schema=ThreatAssessment,
            ),
        )
        return json.loads(response.text)

    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_api_call)
    try:
        return future.result(timeout=timeout_sec)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def analyze_with_resilience(client: genai.Client, prompt: str, models: list[str]) -> dict:
    for attempt in range(1, 3):
        for model_name in models:
            try:
                print(f"  -> Folosesc modelul {model_name}...", flush=True)
                return call_gemini_with_timeout(client, model_name, prompt, timeout_sec=25)
            except FuturesTimeoutError:
                print(f"  [WARN] {model_name} a depasit 25s (rate limit / incarcare). Trec la urmatorul...", flush=True)
            except Exception as e:
                print(f"  [WARN] Eroare pe {model_name}: {str(e)[:120]}. Trec la urmatorul...", flush=True)

        if attempt < 2:
            print("  [INFO] Astept 20s pentru resetarea limitei Free Tier RPM...", flush=True)
            time.sleep(20)

    raise RuntimeError("Niciun model nu a raspuns in timp util. Reincearca peste 1 minut.")


def run_ai_triage():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("Lipseste GEMINI_API_KEY in fisierul .env!")

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Nu am gasit {INPUT_FILE}. Ruleaza intai bigdata_aggregator.py!")

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        suspicious_profiles = json.load(f)

    client = genai.Client(api_key=api_key)
    models = get_prioritized_models(client)
    final_reports = []
    total = len(suspicious_profiles)

    print(f"[INFO] Ordine modele: {models}")
    print(f"[INFO] Trimit {total} profiluri suspecte catre AI pentru analiza...\n", flush=True)

    for idx, profile in enumerate(suspicious_profiles, start=1):
        ip = profile["src_ip"]
        print(f"[{idx}/{total}] Analizez IP-ul {ip}...", flush=True)

        prompt = f"Analyze the following aggregated telemetry for source IP {ip}:\n{json.dumps(profile, indent=2)}"
        assessment = analyze_with_resilience(client, prompt, models)

        report_entry = {
            "source_ip": ip,
            "telemetry_summary": {
                "total_requests": profile["total_requests"],
                "requests_per_minute": profile["requests_per_minute"],
                "total_mb_transferred": profile["total_mb_transferred"],
                "user_agents": profile["user_agents"],
            },
            "ai_triage": assessment,
        }
        final_reports.append(report_entry)

        print(f"=== IP: {ip} ===")
        print(f"  Atac:       {assessment['attack_classification']} ({assessment['severity']})")
        print(f"  MITRE:      {assessment['mitre_attack_technique']}")
        print(f"  Incredere:  {assessment['confidence_score']}%")
        print(f"  Rezumat:    {assessment['technical_summary']}\n", flush=True)

        if idx < total:
            time.sleep(6)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_reports, f, indent=2, ensure_ascii=False)

    print(f"[OK] Raportul complet SOC a fost salvat in {OUTPUT_FILE}")


if __name__ == "__main__":
    run_ai_triage()