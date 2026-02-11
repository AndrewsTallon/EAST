"""FastAPI web interface for EAST scans."""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import os
import pkgutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from east.cli import _get_tests_to_run, _register_tests, TEST_REGISTRY
from east.config import EASTConfig
from east.report import EASTReportGenerator
from east.scan_engine import ScanEngine
from east.utils.validators import sanitize_domain, validate_domain

logger = logging.getLogger(__name__)
app = FastAPI(title="EAST Web UI")


DATA_DIR = Path(os.environ.get("EAST_DATA_DIR", "artifacts/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
JOBS_DB_PATH = DATA_DIR / "jobs.json"

def _discover_test_modules():
    """Import all modules inside east.tests so scanner classes are available.

    Uses pkgutil to walk the package — no module names are hardcoded.
    Each module is imported exactly once (Python caches in sys.modules).
    """
    import east.tests as _pkg

    for finder, module_name, ispkg in pkgutil.iter_modules(_pkg.__path__):
        full_name = f"east.tests.{module_name}"
        try:
            importlib.import_module(full_name)
        except Exception:
            logger.warning("Failed to import scanner module %s", full_name, exc_info=True)




def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    val = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            return dt
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


def _save_jobs_to_disk():
    payload = {"jobs": [_serialize_job(j, include_logs=True) for j in JOBS.values()]}
    tmp = JOBS_DB_PATH.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    tmp.replace(JOBS_DB_PATH)


def _load_jobs_from_disk():
    if not JOBS_DB_PATH.exists():
        return
    try:
        payload = json.loads(JOBS_DB_PATH.read_text(encoding='utf-8'))
    except Exception:
        logger.warning("Failed to load persisted jobs database", exc_info=True)
        return

    for item in payload.get("jobs", []):
        job = JobState(
            id=item["id"],
            status=item.get("status", "queued"),
            created_at=_parse_dt(item.get("created_at")) or datetime.utcnow(),
            completed_at=_parse_dt(item.get("completed_at")),
            client=item.get("client", ""),
            output_path=item.get("output_path", ""),
            domains=item.get("domains", []),
            tests=item.get("tests", []),
            logs=item.get("logs", []),
            results=item.get("results", {}),
            test_status=item.get("test_status", {}),
            config_snapshot=item.get("config_snapshot", {}),
        )
        JOBS[job.id] = job

@app.on_event("startup")
async def _load_scanners():
    """Discover and register all scanner modules once at application startup."""
    _discover_test_modules()
    _register_tests()
    _load_jobs_from_disk()

_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class JobState:
    id: str
    status: str = "queued"
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    client: str = ""
    output_path: str = ""
    domains: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    results: dict[str, Any] = field(default_factory=dict)
    test_status: dict[str, str] = field(default_factory=dict)
    config_snapshot: dict[str, Any] = field(default_factory=dict)


class ScanRequest(BaseModel):
    domains: list[str]
    client: str = "Web UI Client"
    tests: list[str] | None = None
    ssllabs_email: str = ""
    ssllabs_usecache: bool = True


JOBS: dict[str, JobState] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _append_log(job: JobState, message: str):
    line = f"{datetime.utcnow().isoformat()}Z {message}"
    job.logs.append(line)
    logger.info("[job:%s] %s", job.id, message)
    _save_jobs_to_disk()


def _track_test_status(job: JobState, message: str):
    """Parse scan-engine log lines to update per-test status."""
    if "] Starting test: " in message:
        parts = message.split("] Starting test: ", 1)
        if len(parts) == 2:
            domain = parts[0].lstrip("[")
            test_name = parts[1].strip()
            job.test_status[f"{domain}:{test_name}"] = "running"
    elif "] Finished test: " in message:
        parts = message.split("] Finished test: ", 1)
        if len(parts) == 2:
            domain = parts[0].lstrip("[")
            rest = parts[1].strip()
            if rest.endswith("(ok)"):
                test_name = rest[:-4].strip()
                job.test_status[f"{domain}:{test_name}"] = "success"
            elif rest.endswith("(error)"):
                test_name = rest[:-7].strip()
                job.test_status[f"{domain}:{test_name}"] = "failed"


def _serialize_job(job: JobState, include_logs: bool = False) -> dict:
    data = {
        "id": job.id,
        "status": job.status,
        "created_at": job.created_at.isoformat() + "Z",
        "completed_at": (job.completed_at.isoformat() + "Z") if job.completed_at else None,
        "client": job.client,
        "domains": job.domains,
        "tests": job.tests,
        "output_path": job.output_path,
        "results": job.results,
        "test_status": job.test_status,
        "config_snapshot": job.config_snapshot,
    }
    if include_logs:
        data["logs"] = job.logs
    return data


async def _run_job(job: JobState, config: EASTConfig):
    def log_and_track(message: str):
        _append_log(job, message)
        _track_test_status(job, message)

    try:
        job.status = "running"
        # Mark all tests as queued initially
        for domain in job.domains:
            for test in job.tests:
                job.test_status[f"{domain}:{test}"] = "queued"

        log_and_track(f"Starting scan for domains={job.domains}, tests={job.tests}")
        _register_tests()
        engine = ScanEngine(TEST_REGISTRY)
        results = await engine.run(config, job.tests, on_log=log_and_track)

        output_dir = Path("artifacts/web")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"EAST_web_{job.id}.docx"

        report = EASTReportGenerator(config)
        for domain, domain_results in results.items():
            report.add_results(domain, domain_results)

        report.generate(str(output_path))
        job.output_path = str(output_path)
        job.results = {
            domain: [
                {
                    "test_name": r.test_name,
                    "success": r.success,
                    "grade": r.grade,
                    "score": r.score,
                    "error": r.error,
                    "summary": r.summary,
                    "recommendations": r.recommendations,
                }
                for r in domain_results
            ]
            for domain, domain_results in results.items()
        }
        job.status = "completed"
        job.completed_at = datetime.utcnow()
        log_and_track(f"Scan complete. Report generated: {job.output_path}")
    except Exception as exc:
        job.status = "failed"
        job.completed_at = datetime.utcnow()
        log_and_track(f"Job failed: {exc}")


# ---------------------------------------------------------------------------
# SPA shell
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    html_path = _STATIC_DIR / "index.html"
    if html_path.exists():
        return html_path.read_text()
    # Fallback to legacy form if static files not present
    _register_tests()
    options = "\n".join(
        f'<label><input type="checkbox" name="tests" value="{name}" checked> {name}</label><br>'
        for name in TEST_REGISTRY.keys()
    )
    return f"""
    <html><body>
    <h1>EAST Web Scanner</h1>
    <form action='/scan' method='post'>
      <label>Client name: <input type='text' name='client' value='Web UI Client'></label><br><br>
      <label>Domains (comma-separated):</label><br>
      <input type='text' name='domains' style='width:500px' value='example.com'><br><br>
      <label>Tests:</label><br>
      {options}<br>
      <button type='submit'>Start Scan</button>
    </form>
    </body></html>
    """


# ---------------------------------------------------------------------------
# JSON API endpoints
# ---------------------------------------------------------------------------

@app.get("/api/scanners")
async def api_list_scanners():
    """Return available scanner types with metadata."""
    _register_tests()
    scanners = []
    for key, cls in TEST_REGISTRY.items():
        scanners.append({
            "id": key,
            "name": getattr(cls, "name", key),
            "description": getattr(cls, "description", ""),
        })
    return {"scanners": scanners}


@app.post("/api/scan")
async def api_start_scan(req: ScanRequest):
    """Start a scan job from JSON payload."""
    domain_list = [sanitize_domain(d.strip()) for d in req.domains if d.strip()]
    valid_domains = [d for d in domain_list if validate_domain(d)]
    if not valid_domains:
        raise HTTPException(status_code=400, detail="No valid domains provided.")

    config = EASTConfig.default()
    config.client_info.name = req.client
    config.domains = valid_domains

    if req.ssllabs_email:
        config.ssllabs_email = req.ssllabs_email
    config.ssllabs_usecache = req.ssllabs_usecache

    selected_tests = req.tests if req.tests else _get_tests_to_run(config)

    job_id = str(uuid.uuid4())
    job = JobState(
        id=job_id,
        domains=valid_domains,
        tests=selected_tests,
        client=req.client,
        config_snapshot={
            "domains": valid_domains,
            "client": req.client,
            "tests": selected_tests,
            "ssllabs_email": req.ssllabs_email,
            "ssllabs_usecache": req.ssllabs_usecache,
        },
    )
    JOBS[job_id] = job
    _save_jobs_to_disk()
    asyncio.create_task(_run_job(job, config))

    return {
        "job_id": job_id,
        "status_url": f"/api/jobs/{job_id}",
        "logs_url": f"/api/jobs/{job_id}/logs",
    }


@app.get("/api/jobs")
async def api_list_jobs(
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    order: str = Query("desc"),
):
    """List all scan jobs with optional filtering and sorting."""
    jobs = list(JOBS.values())

    if status:
        jobs = [j for j in jobs if j.status == status]

    if search:
        s = search.lower()
        jobs = [
            j for j in jobs
            if s in j.client.lower() or any(s in d.lower() for d in j.domains)
        ]

    reverse = order == "desc"
    if sort_by == "created_at":
        jobs.sort(key=lambda j: j.created_at, reverse=reverse)
    elif sort_by == "status":
        jobs.sort(key=lambda j: j.status, reverse=reverse)
    elif sort_by == "client":
        jobs.sort(key=lambda j: j.client.lower(), reverse=reverse)

    return {
        "jobs": [_serialize_job(j) for j in jobs],
        "total": len(jobs),
    }


@app.get("/api/jobs/{job_id}")
async def api_get_job(job_id: str):
    """Get detailed job status including per-test status."""
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _serialize_job(job, include_logs=True)


@app.get("/api/jobs/{job_id}/results")
async def api_get_results_json(job_id: str):
    """Download scan results as JSON."""
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not job.results:
        raise HTTPException(status_code=400, detail="No results available yet")
    return {
        "job_id": job.id,
        "client": job.client,
        "domains": job.domains,
        "tests": job.tests,
        "status": job.status,
        "created_at": job.created_at.isoformat() + "Z",
        "completed_at": (job.completed_at.isoformat() + "Z") if job.completed_at else None,
        "results": job.results,
    }


# ---------------------------------------------------------------------------
# Legacy form-based endpoints (backward compat)
# ---------------------------------------------------------------------------

@app.post("/scan")
async def start_scan(
    domains: str = Form(...),
    client: str = Form("Web UI Client"),
    tests: list[str] | None = Form(default=None),
):
    domain_list = [sanitize_domain(d.strip()) for d in domains.split(",") if d.strip()]
    valid_domains = [d for d in domain_list if validate_domain(d)]
    if not valid_domains:
        raise HTTPException(status_code=400, detail="No valid domains provided.")

    config = EASTConfig.default()
    config.client_info.name = client
    config.domains = valid_domains

    selected_tests = tests if tests else _get_tests_to_run(config)

    job_id = str(uuid.uuid4())
    job = JobState(
        id=job_id,
        domains=valid_domains,
        tests=selected_tests,
        client=client,
        config_snapshot={
            "domains": valid_domains,
            "client": client,
            "tests": selected_tests,
        },
    )
    JOBS[job_id] = job
    _save_jobs_to_disk()
    asyncio.create_task(_run_job(job, config))

    return {"job_id": job_id, "status_url": f"/jobs/{job_id}", "logs_url": f"/jobs/{job_id}/logs"}


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _serialize_job(job)


@app.get("/jobs/{job_id}/logs")
async def stream_logs(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_stream():
        index = 0
        while True:
            while index < len(job.logs):
                payload = json.dumps({"line": job.logs[index], "status": job.status})
                index += 1
                yield f"data: {payload}\n\n"

            if job.status in {"completed", "failed"}:
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/jobs/{job_id}/download")
async def download_report(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed" or not job.output_path:
        raise HTTPException(status_code=400, detail="Report is not ready yet")

    return FileResponse(
        path=job.output_path,
        filename=Path(job.output_path).name,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
