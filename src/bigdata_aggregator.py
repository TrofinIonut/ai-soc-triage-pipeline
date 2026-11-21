import json
import os
import duckdb

INPUT_FILE = os.path.join("data", "raw_security_logs.jsonl")
OUTPUT_FILE = os.path.join("data", "suspicious_profiles.json")


def run_bigdata_aggregation():
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Nu am gasit {INPUT_FILE}. Ruleaza intai generate_logs.py!")

    con = duckdb.connect(database=":memory:")

    query = f"""
    WITH ip_metrics AS (
        SELECT
            src_ip,
            COUNT(*) AS total_requests,
            ROUND(
                COUNT(*) / GREATEST(
                    EPOCH(MAX(CAST(timestamp AS TIMESTAMP)) - MIN(CAST(timestamp AS TIMESTAMP))) / 60.0,
                    0.1
                ), 2
            ) AS requests_per_minute,
            SUM(CASE WHEN status_code = 401 THEN 1 ELSE 0 END) AS auth_failures_401,
            SUM(CASE WHEN status_code IN (403, 500) THEN 1 ELSE 0 END) AS blocked_or_server_err,
            SUM(CASE WHEN status_code = 404 THEN 1 ELSE 0 END) AS not_found_404,
            ROUND(SUM(bytes_sent) / (1024.0 * 1024.0), 2) AS total_mb_transferred,
            COUNT(DISTINCT endpoint) AS unique_endpoints,
            LIST(DISTINCT user_agent) AS user_agents,
            list_slice(LIST(DISTINCT endpoint), 1, 5) AS sample_endpoints
        FROM read_json_auto('{INPUT_FILE}')
        GROUP BY src_ip
    )
    SELECT *
    FROM ip_metrics
    WHERE auth_failures_401 > 20
       OR blocked_or_server_err > 20
       OR not_found_404 > 30
       OR total_mb_transferred > 50.0
    ORDER BY total_requests DESC;
    """

    cursor = con.execute(query)
    columns = [desc[0] for desc in cursor.description]
    suspicious_records = [dict(zip(columns, row)) for row in cursor.fetchall()]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(suspicious_records, f, indent=2, ensure_ascii=False)

    print(f"[OK] Analiza Big Data finalizata. Din 50.000 de evenimente, au fost izolate {len(suspicious_records)} IP-uri suspecte:\n")
    for rec in suspicious_records:
        print(
            f" -> IP: {rec['src_ip']:16} | Req: {rec['total_requests']:4} | "
            f"401: {rec['auth_failures_401']:3} | 403/500: {rec['blocked_or_server_err']:3} | "
            f"404: {rec['not_found_404']:3} | Trafic: {rec['total_mb_transferred']} MB"
        )
    print(f"\n[OK] Profilurile agregate au fost salvate in {OUTPUT_FILE}")


if __name__ == "__main__":
    run_bigdata_aggregation()