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
            cmd, _ = runner._build_lighthouse_command("out.json")

        self.assertTrue(cmd[0].lower().endswith("npx.cmd"))
        self.assertEqual(cmd[1:3], ["--yes", "lighthouse"])

    def test_windows_reports_node_missing(self):
        runner = PerformanceTestRunner("example.com")

        with patch("east.tests.performance_test.os.name", "nt"), patch(
            "east.tests.performance_test.shutil.which", return_value=None
        ):
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


if __name__ == "__main__":
    unittest.main()
