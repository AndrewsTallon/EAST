import asyncio
import io
import tempfile
import unittest
from pathlib import Path

from fastapi import UploadFile
from starlette.datastructures import Headers

import east.web.app as web_app


class WebLogoManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.original_data_dir = web_app.DATA_DIR
        self.original_logos_dir = web_app.LOGOS_DIR
        self.original_db_path = web_app.JOBS_DB_PATH
        self.original_jobs = dict(web_app.JOBS)

        tmp_path = Path(self.tmp.name)
        web_app.DATA_DIR = tmp_path
        web_app.LOGOS_DIR = tmp_path / "logos"
        web_app.LOGOS_DIR.mkdir(parents=True, exist_ok=True)
        web_app.JOBS_DB_PATH = tmp_path / "jobs.json"

        web_app.JOBS.clear()
        web_app.DELETED_JOB_IDS.clear()

    def tearDown(self):
        web_app.JOBS.clear()
        web_app.JOBS.update(self.original_jobs)
        web_app.DELETED_JOB_IDS.clear()
        web_app.DATA_DIR = self.original_data_dir
        web_app.LOGOS_DIR = self.original_logos_dir
        web_app.JOBS_DB_PATH = self.original_db_path

    def _upload_file(self, name: str, content: bytes) -> UploadFile:
        headers = Headers({"content-type": "image/png"})
        return UploadFile(filename=name, file=io.BytesIO(content), headers=headers)

    def test_logo_upload_and_list(self):
        upload = self._upload_file("client-logo.png", b"png-data")
        created = asyncio.run(web_app.api_upload_logo(file=upload))

        self.assertTrue(created["path"].endswith(".png"))
        self.assertTrue(Path(created["path"]).exists())

        listed = asyncio.run(web_app.api_list_logos())
        self.assertEqual(len(listed["logos"]), 1)
        self.assertEqual(listed["logos"][0]["path"], created["path"])

    def test_scan_snapshot_keeps_logo_path(self):
        logo_file = web_app.LOGOS_DIR / "existing.png"
        logo_file.write_bytes(b"png-data")

        req = web_app.ScanRequest(
            domains=["example.com"],
            client="Logo Client",
            tests=["ssl_labs"],
            ssllabs_email="analyst@example.com",
            company_name="Brand Co",
            logo_path=str(logo_file),
        )

        response = asyncio.run(web_app.api_start_scan(req))
        job = web_app.JOBS[response["job_id"]]

        self.assertEqual(job.config_snapshot["logo_path"], str(logo_file))


if __name__ == "__main__":
    unittest.main()
