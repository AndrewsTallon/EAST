import unittest
from types import SimpleNamespace
from unittest.mock import patch

from east.tests.performance_test import PerformanceTestRunner


class PerformanceRunnerCommandResolutionTests(unittest.TestCase):
    def test_windows_prefers_lighthouse_cmd(self):
        runner = PerformanceTestRunner("example.com")

        with patch("east.tests.performance_test.os.name", "nt"), patch(
            "east.tests.performance_test.shutil.which"
        ) as which_mock:
            which_mock.side_effect = lambda name: {
                "lighthouse.cmd": r"C:\\npm\\lighthouse.cmd",
                "lighthouse.bat": None,
                "lighthouse.exe": None,
            }.get(name)
            with patch.object(runner, "_resolve_chrome_binary", return_value=("/usr/bin/chromium", "mock")):
                cmd, diag = runner._build_lighthouse_command("out.json")

        self.assertTrue(cmd[0].lower().endswith("lighthouse.cmd"))
        self.assertIn("--output=json", cmd)
        self.assertTrue(diag["node_detected"] in (True, False))

    def test_windows_falls_back_to_npx_cmd(self):
        runner = PerformanceTestRunner("example.com")

        with patch("east.tests.performance_test.os.name", "nt"), patch(
            "east.tests.performance_test.shutil.which"
        ) as which_mock:
            which_mock.side_effect = lambda name: {
                "lighthouse.cmd": None,
                "lighthouse.bat": None,
                "lighthouse.exe": None,
                "npx.cmd": r"C:\\npm\\npx.cmd",
                "npx.exe": None,
                "npx.bat": None,
            }.get(name)
            with patch.object(runner, "_resolve_chrome_binary", return_value=("/usr/bin/chromium", "mock")):
                cmd, _ = runner._build_lighthouse_command("out.json")

        self.assertTrue(cmd[0].lower().endswith("npx.cmd"))
        self.assertEqual(cmd[1:3], ["--yes", "lighthouse"])

    def test_windows_reports_node_missing(self):
        runner = PerformanceTestRunner("example.com")

        with patch("east.tests.performance_test.os.name", "nt"), patch(
            "east.tests.performance_test.shutil.which", return_value=None
        ):
            with patch.object(runner, "_resolve_chrome_binary", return_value=("/usr/bin/chromium", "mock")):
                with self.assertRaises(RuntimeError) as err:
                    runner._build_lighthouse_command("out.json")

        self.assertIn("Node.js/npm", str(err.exception))

    def test_windows_rejects_ps1_shim_resolution(self):
        runner = PerformanceTestRunner("example.com")

        with patch("east.tests.performance_test.os.name", "nt"), patch(
            "east.tests.performance_test.shutil.which"
        ) as which_mock:
            which_mock.side_effect = lambda name: {
                "lighthouse.cmd": None,
                "lighthouse.bat": None,
                "lighthouse.exe": None,
                "npx.cmd": None,
                "npx.exe": None,
                "npx.bat": None,
                "lighthouse": r"C:\npm\lighthouse.ps1",
                "node": r"C:\Program Files\nodejs\node.exe",
                "npm": r"C:\Program Files\nodejs\npm.cmd",
                "npm.cmd": r"C:\Program Files\nodejs\npm.cmd",
            }.get(name)
            with patch.object(runner, "_resolve_chrome_binary", return_value=("/usr/bin/chromium", "mock")):
                with self.assertRaises(RuntimeError) as err:
                    runner._build_lighthouse_command("out.json")

        self.assertIn(".ps1 shim", str(err.exception))

    def test_windows_chrome_flags_have_plain_user_data_dir(self):
        runner = PerformanceTestRunner("genwayhome.com")

        with patch("east.tests.performance_test.os.name", "nt"), patch(
            "east.tests.performance_test.os.environ", {"LOCALAPPDATA": r"C:\Users\andre\AppData\Local"}
        ):
            flags = runner._build_chrome_flags(r"C:\Users\andre\AppData\Local\EAST\lighthouse_profiles\genwayhome.com")

        self.assertIn(
            r"--user-data-dir=C:\Users\andre\AppData\Local\EAST\lighthouse_profiles\genwayhome.com",
            flags,
        )
        self.assertNotIn("'\"'\"'", flags)

    def test_eperm_cleanup_failure_uses_existing_json(self):
        runner = PerformanceTestRunner("example.com")
        with patch("east.tests.performance_test.tempfile.NamedTemporaryFile") as tmp_mock, patch(
            "east.tests.performance_test.subprocess.run"
        ) as run_mock, patch.object(
            runner, "_build_lighthouse_command", return_value=(["lighthouse"], {"executable": "lighthouse"})
        ), patch.object(
            runner, "_build_lighthouse_env", return_value=None
        ), patch("east.tests.performance_test.os.path.exists", return_value=True), patch(
            "east.tests.performance_test.open", unittest.mock.mock_open(read_data='{"categories": {"performance": {"score": 0.91}, "accessibility": {"score": 0.87}, "best-practices": {"score": 0.92}, "seo": {"score": 0.89}}}')
        ):
            tmp_mock.return_value.__enter__.return_value = SimpleNamespace(name="out.json")
            run_mock.return_value = SimpleNamespace(returncode=1, stderr="EPERM: destroyTmp failed", stdout="")

            result = runner._run_lighthouse_local()

        self.assertTrue(result.success)
        self.assertEqual(result.details["performance"], 91)

    def test_windows_subprocess_env_uses_stable_tmp(self):
        runner = PerformanceTestRunner("example.com")

        with patch("east.tests.performance_test.os.name", "nt"), patch(
            "east.tests.performance_test.os.environ",
            {"LOCALAPPDATA": r"C:\Users\andre\AppData\Local", "PATH": "x"},
        ), patch("east.tests.performance_test.os.makedirs") as makedirs_mock:
            env = runner._build_lighthouse_env()

        self.assertEqual(env["TEMP"], r"C:\Users\andre\AppData\Local\EAST\tmp")
        self.assertEqual(env["TMP"], r"C:\Users\andre\AppData\Local\EAST\tmp")
        makedirs_mock.assert_called_once_with(r"C:\Users\andre\AppData\Local\EAST\tmp", exist_ok=True)


class PerformanceRunnerPresentationDepthTests(unittest.TestCase):
    def test_parse_lighthouse_result_includes_cwv_and_top_opportunities(self):
        runner = PerformanceTestRunner("example.com")
        payload = {
            "categories": {
                "performance": {"score": 0.84},
                "accessibility": {"score": 0.91},
                "best-practices": {"score": 0.88},
                "seo": {"score": 0.93},
            },
            "audits": {
                "largest-contentful-paint": {"numericValue": 2600},
                "interaction-to-next-paint": {"numericValue": 620},
                "cumulative-layout-shift": {"numericValue": 0.06},
                "first-contentful-paint": {"numericValue": 1700},
                "total-blocking-time": {"numericValue": 240},
                "Reduce unused JavaScript": {
                    "title": "Reduce unused JavaScript",
                    "score": 0.3,
                    "details": {"overallSavingsMs": 820, "overallSavingsBytes": 45000},
                },
                "Serve images in next-gen formats": {
                    "title": "Serve images in next-gen formats",
                    "score": 0.2,
                    "details": {"overallSavingsMs": 200, "overallSavingsBytes": 180000},
                },
                "Eliminate render-blocking resources": {
                    "title": "Eliminate render-blocking resources",
                    "score": 0.4,
                    "details": {"overallSavingsMs": 540, "overallSavingsBytes": 0},
                },
                "Properly size images": {
                    "title": "Properly size images",
                    "score": 1,
                    "details": {"overallSavingsMs": 999, "overallSavingsBytes": 99999},
                },
            },
        }

        result = runner._parse_lighthouse_result(payload, source="Lighthouse Local")

        self.assertIn("Assessment Context", result.summary)
        self.assertEqual(result.tables[0]["title"], "Performance Metrics")

        cwv_table = next(table for table in result.tables if table["title"] == "Core Web Vitals")
        self.assertEqual(cwv_table["headers"], ["Metric", "Value", "Status", "Interpretation"])
        self.assertEqual(cwv_table["rows"][0][0:3], ["LCP", "2.60s", "Needs Improvement"])
        self.assertIn("largest above-the-fold content", cwv_table["rows"][0][3])
        self.assertEqual(cwv_table["rows"][1][0:3], ["INP", "620ms", "Poor"])
        self.assertIn("long JavaScript tasks", cwv_table["rows"][1][3])
        self.assertEqual(
            cwv_table["rows"][2],
            ["CLS", "0.06", "Good", "Measures unexpected layout movement while the page loads or updates."],
        )

        supporting_table = next(table for table in result.tables if table["title"] == "Supporting Metrics")
        self.assertEqual(supporting_table["rows"], [["FCP", "1.70s", "Good"], ["TBT", "240ms", "Needs Improvement"]])

        opp_table = next(table for table in result.tables if table["title"] == "Top Performance Opportunities")
        self.assertEqual(len(opp_table["rows"]), 3)
        self.assertEqual(opp_table["rows"][0][0], "Reduce unused JavaScript")
        self.assertIn("Cause:", opp_table["rows"][0][1])
        self.assertIn("Impact:", opp_table["rows"][0][1])
        self.assertIn("JavaScript payloads", opp_table["rows"][0][1])

    def test_top_opportunities_limits_to_three(self):
        runner = PerformanceTestRunner("example.com")
        audits = {}
        for idx in range(7):
            audits[f"audit-{idx}"] = {
                "title": f"Opportunity {idx}",
                "score": 0.5,
                "details": {"overallSavingsMs": 100 + idx, "overallSavingsBytes": 0},
            }

        rows = runner._build_top_opportunities_rows(audits)

        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][0], "Opportunity 6")

    def test_recommendations_require_optimization_when_any_core_vital_is_poor(self):
        runner = PerformanceTestRunner("example.com")
        recommendations = runner._recommendations(
            [
                ["LCP", "2.40s", "Good", "..."],
                ["INP", "620ms", "Poor", "..."],
                ["CLS", "0.08", "Good", "..."],
            ]
        )
        self.assertEqual(recommendations[0]["severity"], "critical")
        self.assertIn("optimization is required", recommendations[0]["text"])

    def test_recommendations_mark_healthy_when_all_core_vitals_are_good(self):
        runner = PerformanceTestRunner("example.com")
        recommendations = runner._recommendations(
            [
                ["LCP", "2.10s", "Good", "..."],
                ["INP", "120ms", "Good", "..."],
                ["CLS", "0.05", "Good", "..."],
            ]
        )
        self.assertEqual(recommendations[0]["severity"], "info")
        self.assertIn("performance posture is healthy", recommendations[0]["text"])


if __name__ == "__main__":
    unittest.main()
