import unittest
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


if __name__ == "__main__":
    unittest.main()
