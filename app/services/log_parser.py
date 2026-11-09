import csv, io, re
from datetime import datetime, timezone

SSH_RE = re.compile(
    r"(?P<timestamp>\\w{3}\\s+\\d{1,2}\\s[\\d:]+).*?"
    r"(?P<event>Failed password|Accepted password|Invalid user).*?"
    r"(?:for\\s+(?:invalid user\\s+)?(?P<user>[\\w.@-]+)\\s+)?"
    r"from\\s+(?P<source_ip>\\d{1,3}(?:\\.\\d{1,3}){3})"
)

def valid_ip(value):
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def parse_log_text(text):
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    if not lines:
        return []
    if lines[0].lower().startswith("timestamp,"):
        result = []
        for row in csv.DictReader(io.StringIO(text)):
            ip = (row.get("source_ip") or row.get("ip") or "").strip()
            if not valid_ip(ip):
                continue
            event = (row.get("event") or "").strip().lower()
            status = (row.get("status") or "").strip().lower()
            if not event:
                event = "failed_login" if status in {"failed", "failure", "denied"} else "successful_login"
            result.append({"timestamp": row.get("timestamp", ""), "source_ip": ip,
                           "event": event, "user": row.get("user", "unknown")})
        return result
    year = datetime.now(timezone.utc).year
    result = []
    for line in lines:
        match = SSH_RE.search(line)
        if match:
            d = match.groupdict()
            result.append({"timestamp": f"{year} {d['timestamp']}", "source_ip": d["source_ip"],
                           "event": "successful_login" if d["event"].lower().startswith("accepted") else "failed_login",
                           "user": d.get("user") or "unknown"})
    return result
