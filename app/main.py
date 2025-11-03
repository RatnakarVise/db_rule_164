from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import re
import json

app = FastAPI(
    title="ABAP DESCRIBE TABLE Replacement — S/4HANA Modernization (LINES Function)",
    version="1.0"
)

# --- Replacement pattern ---
OBSOLETE_PATTERN = "DESCRIBE TABLE … LINES"
REPLACEMENT_PATTERN = "LINES( … )"

# --- Models ---
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    describe_findings: Optional[List[Finding]] = None

# --- Regex for detecting obsolete DESCRIBE TABLE statements ---
DESCRIBE_TABLE_RE = re.compile(
    r"""
    DESCRIBE\s+TABLE\s+        # detect DESCRIBE TABLE keyword
    (?P<table>\w+)\s+          # capture table variable name
    LINES\s+(?P<target>\w+)    # capture variable receiving line count
    """,
    re.IGNORECASE | re.VERBOSE
)

# --- Utility functions ---
def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def snippet_at(text: str, start: int, end: int) -> str:
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

# --- Suggestion builder ---
def make_generic_suggestion(table: str, target: str) -> str:
    return (
        f"Replace obsolete 'DESCRIBE TABLE {table} LINES {target}' "
        f"with modern expression 'DATA({target}) = LINES( {table} ).' "
        f"This uses the S/4HANA-compatible LINES() function."
    )

# --- Core scan logic ---
def scan_unit(unit: Unit) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    for m in DESCRIBE_TABLE_RE.finditer(src):
        table = m.group("table")
        target = m.group("target")
        stmt_text = m.group(0)

        finding = {
            "pgm_name": unit.pgm_name,
            "inc_name": unit.inc_name,
            "type": unit.type,
            "name": unit.name,
            "start_line": unit.start_line,
            "end_line": unit.end_line,
            "issue_type": "ObsoleteDescribeTableUsage",
            "severity": "warning",
            "line": line_of_offset(src, m.start()),
            "message": (
                f"Obsolete 'DESCRIBE TABLE {table} LINES {target}' found. "
                f"Use LINES( {table} ) instead for S/4HANA compatibility."
            ),
            "suggestion": make_generic_suggestion(table, target),
            "snippet": snippet_at(src, m.start(), m.end()),
            "meta": {
                "original_statement": stmt_text.strip(),
                "replacement_syntax": f"DATA({target}) = LINES( {table} ).",
                "note": "Replaces DESCRIBE TABLE … LINES with functional expression."
            }
        }
        findings.append(finding)

    obj = unit.model_dump()
    obj["describe_findings"] = findings
    return obj

# --- Endpoint ---
@app.post("/remediate-array")
async def scan_describe_table(units: List[Unit]):
    results = []
    for u in units:
        res = scan_unit(u)
        if res["describe_findings"]:
            results.append(res)
    return results

@app.get("/health")
async def health():
    return {"ok": True}
