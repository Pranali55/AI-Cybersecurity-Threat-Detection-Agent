from collections import defaultdict, Counter
from ipaddress import ip_address

def analyze_events(events):
    groups = defaultdict(list)
    for event in events:
        groups[event["source_ip"]].append(event)
    alerts = []
    for ip, rows in groups.items():
        failed = sum("fail" in r["event"].lower() or "invalid" in r["event"].lower() for r in rows)
        success = sum("success" in r["event"].lower() or "accepted" in r["event"].lower() for r in rows)
        try:
            external = ip_address(ip).is_global
        except ValueError:
            external = False
        if failed >= 5:
            severity = "critical" if failed >= 20 else "high" if failed >= 10 else "medium"
            alerts.append({
                "source_ip": ip, "category": "Repeated authentication failures",
                "severity": severity, "risk_score": min(100, 35 + failed * 3),
                "failed_attempts": failed, "successful_attempts": success,
                "evidence": f"{failed} failed authentication events observed from this source.",
                "recommendation": "Validate whether activity is expected. Review MFA, account protection, rate limits, and identity logs."
            })
        if failed >= 5 and success:
            alerts.append({
                "source_ip": ip, "category": "Successful login after repeated failures",
                "severity": "high", "risk_score": min(100, 65 + failed),
                "failed_attempts": failed, "successful_attempts": success,
                "evidence": "A successful login and five or more failures were recorded for this source.",
                "recommendation": "Verify the login with the account owner and review session activity through your approved incident process."
            })
        if external and failed >= 3:
            alerts.append({
                "source_ip": ip, "category": "External source with repeated failures",
                "severity": "medium", "risk_score": min(85, 30 + failed * 4),
                "failed_attempts": failed, "successful_attempts": success,
                "evidence": "A globally routable IP generated repeated failed authentication events.",
                "recommendation": "Correlate with approved threat-intelligence, firewall, and identity-provider telemetry."
            })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: (order[a["severity"]], -a["risk_score"]))
    counts = Counter(a["severity"] for a in alerts)
    return {"summary": {
        "total_events": len(events), "unique_source_ips": len(groups),
        "failed_logins": sum("fail" in e["event"].lower() or "invalid" in e["event"].lower() for e in events),
        "successful_logins": sum("success" in e["event"].lower() or "accepted" in e["event"].lower() for e in events),
        "alerts": len(alerts), "critical_alerts": counts["critical"],
        "high_alerts": counts["high"], "medium_alerts": counts["medium"]
    }, "alerts": alerts, "events": events[:500],
    "methodology": "Explainable rules over uploaded authentication logs. Alerts are investigation leads, not proof of compromise."}
