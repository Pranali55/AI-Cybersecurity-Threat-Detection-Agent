def build_report(result):
    s = result["summary"]
    lines = ["# Security Log Analysis Report", "", "## Executive summary",
        f"- Events analysed: {s['total_events']}", f"- Unique source IPs: {s['unique_source_ips']}",
        f"- Failed logins: {s['failed_logins']}", f"- Successful logins: {s['successful_logins']}",
        f"- Alerts: {s['alerts']}", "", "## Findings"]
    if not result["alerts"]:
        lines.append("- No configured alert conditions were triggered.")
    for a in result["alerts"]:
        lines += [f"### {a['severity'].upper()}: {a['category']}", f"- Source: `{a['source_ip']}`",
                  f"- Risk score: {a['risk_score']}/100", f"- Evidence: {a['evidence']}",
                  f"- Recommended review: {a['recommendation']}", ""]
    lines += ["## Limitations", "- Analysis covers only the uploaded data.",
              "- An alert is not proof of malicious activity or compromise.",
              "- Correlate with other telemetry and follow your incident-response process.",
              "- No blocking, scanning, account changes, or automated response actions are performed."]
    return "\n".join(lines)
