import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import east.web.app as web_app


class WebJobPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.original_db_path = web_app.JOBS_DB_PATH
        self.original_jobs = dict(web_app.JOBS)

        web_app.JOBS.clear()
        web_app.JOBS_DB_PATH = Path(self.tmp.name) / "jobs.json"

    def tearDown(self):
        web_app.JOBS.clear()
        web_app.JOBS.update(self.original_jobs)
        web_app.JOBS_DB_PATH = self.original_db_path

    def test_save_preserves_jobs_from_other_workers(self):
        created_at = datetime.utcnow() - timedelta(minutes=10)
        disk_payload = {
            "jobs": [
                {
                    "id": "job-on-disk",
                    "status": "running",
                    "created_at": created_at.isoformat() + "Z",
                    "completed_at": None,
                    "client": "Disk Worker",
                    "domains": ["disk.example"],
                    "tests": ["dns_lookup"],
                    "output_path": "",
                    "results": {},
                    "test_status": {"disk.example:dns_lookup": "running"},
                    "config_snapshot": {},
                    "logs": ["2026-01-01T00:00:00Z still running"],
                }
            ]
        }
        web_app.JOBS_DB_PATH.write_text(json.dumps(disk_payload), encoding="utf-8")

        web_app.JOBS["job-in-memory"] = web_app.JobState(
            id="job-in-memory",
            status="queued",
            created_at=datetime.utcnow(),
            domains=["mem.example"],
            tests=["ssl_labs"],
            client="Memory Worker",
        )

        web_app._save_jobs_to_disk()

        merged = json.loads(web_app.JOBS_DB_PATH.read_text(encoding="utf-8"))
        job_ids = {job["id"] for job in merged["jobs"]}
        self.assertSetEqual(job_ids, {"job-on-disk", "job-in-memory"})

    def test_sync_loads_jobs_created_by_other_workers(self):
        created_at = datetime.utcnow() - timedelta(minutes=2)
        payload = {
            "jobs": [
                {
                    "id": "external-job",
                    "status": "completed",
                    "created_at": created_at.isoformat() + "Z",
                    "completed_at": (created_at + timedelta(minutes=1)).isoformat() + "Z",
                    "client": "External Worker",
                    "domains": ["external.example"],
                    "tests": ["security_headers"],
                    "output_path": "artifacts/web/report.docx",
                    "results": {"external.example": []},
                    "test_status": {"external.example:security_headers": "success"},
                    "config_snapshot": {},
                    "logs": ["2026-01-01T00:00:00Z done"],
                }
            ]
        }
        web_app.JOBS_DB_PATH.write_text(json.dumps(payload), encoding="utf-8")

        self.assertNotIn("external-job", web_app.JOBS)
        web_app._sync_jobs_from_disk()

        self.assertIn("external-job", web_app.JOBS)
        self.assertEqual(web_app.JOBS["external-job"].status, "completed")
        self.assertEqual(web_app.JOBS["external-job"].domains, ["external.example"])


if __name__ == "__main__":
    unittest.main()
