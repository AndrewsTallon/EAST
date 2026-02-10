"""FastAPI web interface for EAST scans."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse

from east.cli import _get_tests_to_run, _register_tests, TEST_REGISTRY
from east.config import EASTConfig
from east.report import EASTReportGenerator
from east.scan_engine import ScanEngine
from east.utils.validators import sanitize_domain, validate_domain

logger = logging.getLogger(__name__)
app = FastAPI(title="EAST Web UI")


@dataclass
class JobState:
    id: str
    status: str = "queued"
    created_at: datetime = field(default_factory=datetime.utcnow)
    output_path: str = ""
    domains: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    results: dict[str, Any] = field(default_factory=dict)


JOBS: dict[str, JobState] = {}


def _append_log(job: JobState, message: str):
    line = f"{datetime.utcnow().isoformat()}Z {message}"
    job.logs.append(line)
    logger.info("[job:%s] %s", job.id, message)


async def _run_job(job: JobState, config: EASTConfig):
    try:
        job.status = "running"
        _append_log(job, f"Starting scan for domains={job.domains}, tests={job.tests}")
        _register_tests()
        engine = ScanEngine(TEST_REGISTRY)
        results = await engine.run(config, job.tests, on_log=lambda m: _append_log(job, m))

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
                }
                for r in domain_results
            ]
            for domain, domain_results in results.items()
        }
        job.status = "completed"
        _append_log(job, f"Scan complete. Report generated: {job.output_path}")
    except Exception as exc:
        job.status = "failed"
        _append_log(job, f"Job failed: {exc}")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
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
    job = JobState(id=job_id, domains=valid_domains, tests=selected_tests)
    JOBS[job_id] = job
    asyncio.create_task(_run_job(job, config))

    return {"job_id": job_id, "status_url": f"/jobs/{job_id}", "logs_url": f"/jobs/{job_id}/logs"}


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": job.id,
        "status": job.status,
        "created_at": job.created_at.isoformat() + "Z",
        "domains": job.domains,
        "tests": job.tests,
        "output_path": job.output_path,
        "results": job.results,
    }


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
