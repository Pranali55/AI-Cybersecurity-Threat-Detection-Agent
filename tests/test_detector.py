from app.services.detector import analyze_events

def test_repeated_failures_generate_alert():
    events = [{"source_ip":"203.0.113.10","event":"failed_login","user":"admin","timestamp":""} for _ in range(6)]
    result = analyze_events(events)
    assert result["summary"]["alerts"] >= 1
    assert result["alerts"][0]["category"] == "Repeated authentication failures"
