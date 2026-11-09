from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from pathlib import Path
from app.services.log_parser import parse_log_text
from app.services.detector import analyze_events
from app.services.report import build_report

app = FastAPI(title="AI Cybersecurity Threat Detection Agent", version="1.0.0")

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if Path(file.filename or "").suffix.lower() not in {".log", ".txt", ".csv"}:
        raise HTTPException(400, "Upload a .log, .txt, or .csv file.")
    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(413, "Maximum upload size is 5 MB.")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be UTF-8 encoded.")
    events = parse_log_text(content)
    if not events:
        raise HTTPException(400, "No supported authentication events found.")
    result = analyze_events(events)
    result["report"] = build_report(result)
    return result
