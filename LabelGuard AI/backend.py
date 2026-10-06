from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from openai import OpenAI
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from starlette.concurrency import run_in_threadpool

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
DB_PATH = Path(os.getenv("DATABASE_PATH", str(ROOT / "labelguard.sqlite3")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(ROOT / "uploads")))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RULE_CONFIG = json.loads((ROOT / "rule_config.json").read_text(encoding="utf-8"))
RULES = RULE_CONFIG["fields"]
RULE_BY_ID = {rule["id"]: rule for rule in RULES}
MAX_IMAGE_BYTES = 8 * 1024 * 1024
ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp"}
TOKEN_TTL_SECONDS = 8 * 60 * 60
DEFAULT_INSPECTOR_PASSWORD_HASH = "$2b$12$dd7ou1lqK8r5aDLX9A39ueV/qg/eH/OdX/j6Sg0XVccziwVzZeuYu"
if os.getenv("ENVIRONMENT", "development").lower() == "production":
    if not os.getenv("JWT_SECRET") or os.getenv("JWT_SECRET") == "dev-only-change-this-jwt-secret":
        raise RuntimeError("Set a unique JWT_SECRET before running in production")
    if not os.getenv("INSPECTOR_PASSWORD_HASH"):
        raise RuntimeError("Set INSPECTOR_PASSWORD_HASH before running in production")

app = FastAPI(title="LabelGuard AI API", version="1.0.0")
logger = logging.getLogger("labelguard")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connection():
    db = sqlite3.connect(DB_PATH, timeout=20)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def initialize_database() -> None:
    with connection() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            user_id TEXT,
            image_ref TEXT NOT NULL,
            extracted_fields TEXT NOT NULL,
            violations TEXT NOT NULL,
            field_results TEXT NOT NULL,
            status TEXT NOT NULL,
            reviewer_notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            reviewed_at TEXT
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id, created_at DESC)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status, created_at DESC)")


initialize_database()


def issue_token(username: str) -> str:
    secret = os.getenv("JWT_SECRET", "dev-only-change-this-jwt-secret")
    now = int(time.time())
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": username, "iat": now, "exp": now + TOKEN_TTL_SECONDS}).encode()).decode().rstrip("=")
    signing_input = f"{header}.{payload}"
    signature = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return f"{signing_input}.{signature}"


def get_inspector(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Inspector login required")
    try:
        header, payload, signature = authorization[7:].split(".")
        signing_input = f"{header}.{payload}"
        expected = base64.urlsafe_b64encode(hmac.new(os.getenv("JWT_SECRET", "dev-only-change-this-jwt-secret").encode(), signing_input.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid signature")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if claims.get("exp", 0) < time.time() or claims.get("sub") != os.getenv("INSPECTOR_USERNAME", "inspector"):
            raise ValueError("expired or invalid subject")
        return claims["sub"]
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Inspector session expired; please log in again") from exc


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class ReviewBody(BaseModel):
    action: str = Field(pattern="^(approve|reject|annotate)$")
    notes: str = Field(default="", max_length=4000)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "LabelGuard AI"}


@app.get("/api/rules")
def get_rules() -> dict[str, Any]:
    return RULE_CONFIG


@app.post("/api/login")
def login(body: LoginBody) -> dict[str, str]:
    username = os.getenv("INSPECTOR_USERNAME", "inspector")
    password_hash = os.getenv("INSPECTOR_PASSWORD_HASH", DEFAULT_INSPECTOR_PASSWORD_HASH)
    try:
        valid = hmac.compare_digest(body.username, username) and bcrypt.checkpw(body.password.encode(), password_hash.encode())
    except ValueError:
        valid = False
    if not valid:
        raise HTTPException(status_code=401, detail="Incorrect inspector username or password")
    return {"token": issue_token(username), "username": username, "expires_in": str(TOKEN_TTL_SECONDS)}


def make_extraction_prompt() -> str:
    field_list = [{"id": item["id"], "label": item["label"]} for item in RULES]
    metadata_fields = RULE_CONFIG["extraction_metadata"]
    return (
        "You extract text only from package-label photos for a prototype. Do not decide legal compliance. "
        "Return JSON only with keys metadata (object) and fields (object). Metadata fields: " + json.dumps(metadata_fields, ensure_ascii=False) + ". "
        "For every supplied field id return {value: string or null, confidence: number from 0 to 1}. "
        "Extract only visible declarations; never infer absent text. Set value null when not legible/not visible. "
        "Use the exact field IDs in this list and no other fields: " + json.dumps(field_list, ensure_ascii=False)
    )


def normalize_extraction(raw: Any) -> tuple[str, bool | None, dict[str, dict[str, Any]]]:
    if not isinstance(raw, dict):
        raise ValueError("Extraction response is not an object")
    src = raw.get("fields", {})
    if not isinstance(src, dict):
        src = {}
    normalized: dict[str, dict[str, Any]] = {}
    for rule in RULES:
        item = src.get(rule["id"], {})
        if isinstance(item, str):
            item = {"value": item, "confidence": 0.75}
        if not isinstance(item, dict):
            item = {}
        value = item.get("value")
        value = value.strip()[:1000] if isinstance(value, str) and value.strip() else None
        try:
            confidence = max(0.0, min(1.0, float(item.get("confidence", 0)))) if value else 0.0
        except (TypeError, ValueError):
            confidence = 0.0
        normalized[rule["id"]] = {"value": value, "confidence": confidence}
    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    product_name = metadata.get("product_name")
    product_name = product_name.strip()[:160] if isinstance(product_name, str) and product_name.strip() else "Unidentified package"
    imported = metadata.get("is_imported") if isinstance(metadata.get("is_imported"), bool) else None
    return product_name, imported, normalized


def run_rule_engine(fields: dict[str, dict[str, Any]], is_imported: bool | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    field_results: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for rule in RULES:
        value = fields[rule["id"]]["value"]
        conditional_unknown = rule["id"] == "country_of_origin" and is_imported is None
        applicable = rule.get("required", False) or (rule["id"] == "country_of_origin" and is_imported is True)
        if rule["id"] == "country_of_origin" and is_imported is False:
            applicable = False
        if conditional_unknown:
            state = "needs_review"
        elif not applicable:
            state = "not_applicable"
        elif value:
            state = "pass"
            reason = ""
            expected = "A legible declaration is visible on the package."
            if rule["id"] == "net_quantity" and not re.search(r"\d+(?:[.,]\d+)?\s*(?:kg|g|mg|l|ml|cl|m|cm|mm|pcs?|pieces?|units?)\b|\b\d+\s*(?:count|no\.?s?)\b", value, re.IGNORECASE):
                state = "fail"
                reason = "A numeric quantity and recognizable unit were not both extracted."
                expected = "A numeric net quantity and applicable unit or count declaration should be clearly declared."
            elif rule["id"] == "mrp" and not re.search(r"(?:₹|\bINR\b|\bRs\.?\s*)\s*\d|\d[\d,.]*\s*(?:₹|\bINR\b|\bRs\b)", value, re.IGNORECASE):
                state = "fail"
                reason = "A retail price and recognizable currency marker were not both extracted."
                expected = "A retail sale price with a recognizable Indian currency marker should be clearly declared."
            elif rule["id"] == "month_year" and not re.search(r"(?:\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\b.{0,8}\b\d{4}\b|\b\d{1,2}[/-]\d{4}\b|\b\d{4}[/-]\d{1,2}\b)", value, re.IGNORECASE):
                state = "fail"
                reason = "A recognizable month-and-year value was not extracted."
                expected = "A recognizable applicable month and year should be declared."
            else:
                reason = "The configured prototype field check did not find a recognizable declaration."
            if state == "fail":
                violations.append({
                    "rule_id": rule["rule_id"], "field": rule["label"],
                    "description": rule["description"], "extracted_value": value,
                    "expected": expected, "reason": reason, "severity": rule["severity"]
                })
        else:
            state = "fail"
            violations.append({
                "rule_id": rule["rule_id"], "field": rule["label"],
                "description": rule["description"], "extracted_value": None,
                "expected": "A legible mandatory declaration should appear on the applicable package surface, subject to the current Rules and any exemption.",
                "reason": "No legible declaration was extracted from the submitted image; confirm the complete package and applicability manually.",
                "severity": rule["severity"]
            })
        field_results.append({
            "field_id": rule["id"], "field": rule["label"], "value": value,
            "confidence": fields[rule["id"]]["confidence"], "status": state,
            "rule_id": rule["rule_id"], "description": rule["description"],
            "severity": rule["severity"], "applicable": applicable
        })
    return field_results, violations


async def extract_label(image_bytes: bytes, mime_type: str) -> dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Vision API is not configured")
    client = OpenAI(api_key=api_key, timeout=8, max_retries=0)
    encoded = base64.b64encode(image_bytes).decode("ascii")
    completion = await run_in_threadpool(lambda: client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        response_format={"type": "json_object"},
        temperature=0,
        max_tokens=1400,
        messages=[
            {"role": "system", "content": make_extraction_prompt()},
            {"role": "user", "content": [
                {"type": "text", "text": "Extract visible declarations from this package label image."},
                {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{encoded}", "detail": "high"}}
            ]}
        ]
    ))
    content = completion.choices[0].message.content
    if not content:
        raise ValueError("Empty vision response")
    return json.loads(content)


def as_scan(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"], "session_id": row["session_id"], "status": row["status"],
        "created_at": row["created_at"], "product_name": json.loads(row["extracted_fields"]).get("product_name"),
        "is_imported": json.loads(row["extracted_fields"]).get("is_imported"),
        "fields": json.loads(row["field_results"]), "violations": json.loads(row["violations"]),
        "reviewer_notes": row["reviewer_notes"], "image_url": f"/api/scans/{row['id']}/image"
    }


@app.post("/api/scans")
async def create_scan(file: UploadFile = File(...), x_session_id: str | None = Header(default=None)) -> dict[str, Any]:
    try:
        session_id = str(uuid.UUID(x_session_id)) if x_session_id else str(uuid.uuid4())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid session identifier") from exc
    mime_type = (file.content_type or "").lower()
    if mime_type not in ALLOWED_MIME:
        raise HTTPException(status_code=415, detail="Upload a JPEG, PNG, or WebP label photo")
    image_bytes = await file.read(MAX_IMAGE_BYTES + 1)
    if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image must be between 1 byte and 8 MB")
    if not image_bytes.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"RIFF")):
        raise HTTPException(status_code=415, detail="The uploaded file does not look like a supported image")
    if mime_type == "image/webp" and image_bytes[8:12] != b"WEBP":
        raise HTTPException(status_code=415, detail="The uploaded file does not look like a supported WebP image")
    try:
        raw = await extract_label(image_bytes, mime_type)
        product_name, is_imported, fields = normalize_extraction(raw)
    except Exception as exc:
        # Technical failures deliberately never create a scan record.
        logger.exception("Label extraction failed")
        raise HTTPException(status_code=502, detail="Something went wrong, please try again.") from exc

    populated = [item for item in fields.values() if item["value"]]
    confidence_values = [item["confidence"] for item in populated]
    if len(populated) <= 1:
        status = "unreadable"
        field_results = [{"field_id": rule["id"], "field": rule["label"], "value": fields[rule["id"]]["value"], "confidence": fields[rule["id"]]["confidence"], "status": "unreadable", "rule_id": rule["rule_id"], "description": rule["description"], "severity": rule["severity"], "applicable": rule.get("required", False)} for rule in RULES]
        violations: list[dict[str, Any]] = []
    else:
        field_results, violations = run_rule_engine(fields, is_imported)
        average_confidence = sum(confidence_values) / max(len(confidence_values), 1)
        if len(populated) < len(RULES) - 1 or average_confidence < 0.68 or any(item["confidence"] < 0.45 for item in populated) or is_imported is None:
            status = "needs_review"
            for field_result in field_results:
                if field_result["confidence"] < 0.68 and field_result["status"] in {"pass", "fail"}:
                    field_result["status"] = "needs_review"
        else:
            status = "fail" if violations else "pass"
    scan_id = str(uuid.uuid4())
    image_name = f"{scan_id}.{mime_type.split('/')[-1].replace('jpeg', 'jpg')}"
    image_path = UPLOAD_DIR / image_name
    image_path.write_bytes(image_bytes)
    stored_fields = {"product_name": product_name, "is_imported": is_imported, "fields": fields}
    try:
        with connection() as db:
            db.execute("INSERT INTO scans (id, session_id, user_id, image_ref, extracted_fields, violations, field_results, status, reviewer_notes, created_at) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, '', ?)",
                       (scan_id, session_id, image_name, json.dumps(stored_fields), json.dumps(violations), json.dumps(field_results), status, utc_now()))
    except Exception:
        image_path.unlink(missing_ok=True)
        raise
    with connection() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    result = as_scan(row)
    result["session_id"] = session_id
    return result


@app.get("/api/history")
def get_history(session_id: str) -> list[dict[str, Any]]:
    try:
        session_id = str(uuid.UUID(session_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid session identifier") from exc
    with connection() as db:
        rows = db.execute("SELECT * FROM scans WHERE session_id = ? ORDER BY created_at DESC LIMIT 100", (session_id,)).fetchall()
    return [as_scan(row) for row in rows]


@app.get("/api/scans/{scan_id}/image")
def get_scan_image(scan_id: str, authorization: str | None = Header(default=None), session_id: str | None = None) -> FileResponse:
    with connection() as db:
        row = db.execute("SELECT image_ref, session_id FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    inspector = False
    if authorization and authorization.startswith("Bearer "):
        try:
            get_inspector(authorization)
            inspector = True
        except HTTPException:
            pass
    if not inspector:
        try:
            allowed = session_id is not None and str(uuid.UUID(session_id)) == row["session_id"]
        except ValueError:
            allowed = False
        if not allowed:
            raise HTTPException(status_code=403, detail="This scan is not available to this session")
    path = UPLOAD_DIR / Path(row["image_ref"]).name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Image evidence not found")
    return FileResponse(path, headers={"Cache-Control": "no-store"})


@app.get("/api/inspector/pending")
def pending_reviews(_: str = Depends(get_inspector)) -> list[dict[str, Any]]:
    with connection() as db:
        rows = db.execute("SELECT * FROM scans WHERE status IN ('needs_review', 'unreadable') ORDER BY created_at ASC").fetchall()
    return [as_scan(row) for row in rows]


@app.post("/api/inspector/scans/{scan_id}/review")
def review_scan(scan_id: str, body: ReviewBody, username: str = Depends(get_inspector)) -> dict[str, Any]:
    if body.action == "annotate" and not body.notes.strip():
        raise HTTPException(status_code=400, detail="Enter a note before annotating")
    with connection() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        if body.action == "approve":
            status = "pass"
        elif body.action == "reject":
            status = "fail"
        else:
            status = row["status"]
        notes = body.notes.strip() if body.action == "annotate" else body.notes.strip() or row["reviewer_notes"]
        db.execute("UPDATE scans SET status = ?, reviewer_notes = ?, reviewed_at = ? WHERE id = ?", (status, notes, utc_now(), scan_id))
        updated = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return as_scan(updated)


@app.get("/api/inspector/dashboard")
def dashboard(_: str = Depends(get_inspector)) -> dict[str, Any]:
    with connection() as db:
        rows = db.execute("SELECT status, violations, field_results FROM scans").fetchall()
    counts: dict[str, int] = {"pass": 0, "fail": 0, "needs_review": 0, "unreadable": 0}
    field_counts: dict[str, dict[str, int]] = {}
    severity = {"high": 0, "medium": 0, "low": 0}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
        for violation in json.loads(row["violations"]):
            sev = violation.get("severity", "medium")
            severity[sev] = severity.get(sev, 0) + 1
        for field in json.loads(row["field_results"]):
            bucket = field_counts.setdefault(field["field"], {"pass": 0, "fail": 0, "needs_review": 0, "not_applicable": 0, "unreadable": 0})
            bucket[field["status"]] = bucket.get(field["status"], 0) + 1
    total = len(rows)
    decided = counts["pass"] + counts["fail"]
    return {"total_scans": total, "pass_rate": round(100 * counts["pass"] / decided) if decided else 0,
            "pending_reviews": counts["needs_review"] + counts["unreadable"], "statuses": counts,
            "severity": severity, "fields": field_counts}


@app.get("/api/inspector/scans/{scan_id}")
def inspector_scan(scan_id: str, _: str = Depends(get_inspector)) -> dict[str, Any]:
    with connection() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return as_scan(row)


@app.get("/api/inspector/scans/{scan_id}/report.pdf")
def report_pdf(scan_id: str, _: str = Depends(get_inspector)) -> Response:
    with connection() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = as_scan(row)
    buffer = __import__("io").BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=38, leftMargin=38, topMargin=38, bottomMargin=38)
    styles = getSampleStyleSheet()
    elements = [Paragraph("LabelGuard AI — Inspector report", styles["Title"]), Spacer(1, 8),
                Paragraph(f"Scan ID: {scan['id']}<br/>Captured: {scan['created_at']}<br/>Overall status: {scan['status'].upper()}<br/>Product: {scan['product_name']}", styles["BodyText"]), Spacer(1, 14)]
    data = [["Field", "Extracted value", "Verdict", "Rule reference"]]
    for field in scan["fields"]:
        data.append([field["field"], field["value"] or "Not legible / not visible", field["status"], field["rule_id"]])
    table = Table(data, repeatRows=1, colWidths=[145, 170, 75, 125])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9e4f5")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#241a35")), ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#b8b3bf")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 7), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f6f9")])]))
    elements.extend([table, Spacer(1, 14), Paragraph("Violations and rule descriptions", styles["Heading2"])])
    if scan["violations"]:
        for violation in scan["violations"]:
            elements.append(Paragraph(f"<b>{violation['rule_id']} — {violation['field']}</b><br/>{violation['description']}<br/>Expected: {violation.get('expected', 'Declaration visible where applicable')}<br/>Extracted: {violation.get('extracted_value') or 'None'}<br/>Reason: {violation['reason']}", styles["BodyText"]))
            elements.append(Spacer(1, 7))
    else:
        elements.append(Paragraph("No missing mandatory declarations were recorded by this prototype scan.", styles["BodyText"]))
    elements.extend([Spacer(1, 12), Paragraph(f"Inspector notes: {scan['reviewer_notes'] or 'None'}", styles["BodyText"]), Spacer(1, 10), Paragraph("Prototype output only. Not a legal opinion. Verify the current consolidated Rules, amendments, exemptions, package context, and all package faces before any enforcement or business decision.", styles["Italic"])])
    doc.build(elements)
    return Response(buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=labelguard-{scan_id}.pdf", "Cache-Control": "no-store"})


# Expose only the intended frontend assets; never serve .env, source, uploads,
# SQLite files, or configuration directly from the project directory.
@app.get("/", include_in_schema=False)
def frontend() -> FileResponse:
    return FileResponse(ROOT / "index.html", media_type="text/html", headers={"Cache-Control": "no-store"})


@app.get("/app.js", include_in_schema=False)
def frontend_script() -> FileResponse:
    return FileResponse(ROOT / "app.js", media_type="text/javascript", headers={"Cache-Control": "no-store"})


@app.get("/styles.css", include_in_schema=False)
def frontend_styles() -> FileResponse:
    return FileResponse(ROOT / "styles.css", media_type="text/css", headers={"Cache-Control": "no-store"})
