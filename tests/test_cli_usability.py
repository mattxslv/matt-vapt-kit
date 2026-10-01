import contextlib
import copy
import getpass
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

import yaml

from test_assessment import approved, observation
from test_roles import Application, ENV, approval_for, configuration
from vaptkit.cli import main, print_assessment_summary
from vaptkit.doctor import diagnose
from vaptkit.process import ToolError
from vaptkit.roles import credentials, run


class PasswordPromptTests(unittest.TestCase):
    def setUp(self):
        self.config = configuration()
        self.approval = approval_for(self.config)
        self.emails = {key: value for key, value in ENV.items() if key != "DTAP_QA_PASSWORD"}

    def test_shared_password_prompt_once_without_environment_mutation(self):
        with patch.dict(os.environ, self.emails, clear=True), patch(
            "vaptkit.roles.sys.stdin.isatty", return_value=True
        ), patch("vaptkit.roles.getpass.getpass", return_value="SYNTHETIC_HIDDEN") as prompt:
            value = credentials(self.config, self.approval, prompt_passwords=True)
            self.assertEqual({item["password"] for item in value.values()}, {"SYNTHETIC_HIDDEN"})
            self.assertNotIn("DTAP_QA_PASSWORD", os.environ)
            prompt.assert_called_once()

    def test_environment_credentials_do_not_prompt_even_without_terminal(self):
        with patch.dict(os.environ, ENV, clear=True), patch("vaptkit.roles.getpass.getpass") as prompt:
            value = credentials(self.config, self.approval, prompt_passwords=True)
            self.assertEqual(value["service-provider"]["password"], ENV["DTAP_QA_PASSWORD"])
            prompt.assert_not_called()

    def test_missing_email_or_no_opt_in_does_not_prompt(self):
        for environment, enabled in (({}, True), (self.emails, False)):
            with patch.dict(os.environ, environment, clear=True), patch(
                "vaptkit.roles.getpass.getpass"
            ) as prompt, self.assertRaises(ToolError):
                credentials(self.config, self.approval, prompt_passwords=enabled)
            prompt.assert_not_called()

    def test_no_plaintext_fallback_or_noninteractive_prompt(self):
        with patch.dict(os.environ, self.emails, clear=True), patch(
            "vaptkit.roles.sys.stdin.isatty", return_value=False
        ), patch("vaptkit.roles.getpass.getpass") as prompt, self.assertRaises(ToolError):
            credentials(self.config, self.approval, prompt_passwords=True)
        prompt.assert_not_called()
        def insecure_prompt(*args):
            warnings.warn("Echo unavailable", getpass.GetPassWarning)
            self.fail("Prompt continued after an unsafe echo warning")
        with patch.dict(os.environ, self.emails, clear=True), patch(
            "vaptkit.roles.sys.stdin.isatty", return_value=True
        ), patch("vaptkit.roles.getpass.getpass", side_effect=insecure_prompt), self.assertRaises(ToolError):
            credentials(self.config, self.approval, prompt_passwords=True)

    def test_cancellation_bad_input_or_expiry_prevents_all_requests(self):
        for response in (EOFError(), KeyboardInterrupt(), "", " trailing ", "x" * 1025, "expired"):
            approval = copy.deepcopy(self.approval)
            def prompt(*args):
                if isinstance(response, BaseException):
                    raise response
                if response == "expired":
                    approval["expires_at"] = "2000-01-01T00:00:00Z"
                return response
            with self.subTest(response_type=type(response).__name__), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "out"
                with patch.dict(os.environ, self.emails, clear=True), patch(
                    "vaptkit.roles.sys.stdin.isatty", return_value=True
                ), patch("vaptkit.roles.getpass.getpass", side_effect=prompt), patch(
                    "vaptkit.roles.request"
                ) as request, patch("vaptkit.roles.browser_login") as browser, self.assertRaises(ToolError):
                    run(self.config, approval, output, prompt_passwords=True)
                request.assert_not_called()
                browser.assert_not_called()
                self.assertFalse(output.exists())

    def test_distinct_password_variables_prompt_separately(self):
        self.config["role_testing"]["accounts"][1]["password_env"] = "OTHER_QA_PASSWORD"
        with patch.dict(os.environ, self.emails, clear=True), patch(
            "vaptkit.roles.sys.stdin.isatty", return_value=True
        ), patch("vaptkit.roles.getpass.getpass", side_effect=["SYNTHETIC_ONE", "SYNTHETIC_TWO"]) as prompt:
            value = credentials(self.config, approval_for(self.config), prompt_passwords=True)
        self.assertEqual(prompt.call_count, 2)
        self.assertNotEqual(value["service-provider"]["password"], value["lead-evaluator"]["password"])

    def test_existing_output_rejected_before_password_prompt(self):
        with tempfile.TemporaryDirectory() as directory, patch("vaptkit.roles.getpass.getpass") as prompt:
            with self.assertRaises(ToolError):
                run(self.config, self.approval, Path(directory), prompt_passwords=True)
        prompt.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Hidden-input PTY check requires POSIX")
    def test_real_terminal_disables_echo_and_never_prints_password(self):
        import errno
        import pty
        import select
        import termios
        import time

        master, slave = pty.openpty()
        code = (
            "from test_roles import configuration, approval_for\n"
            "from vaptkit.roles import credentials\n"
            "config = configuration()\n"
            "value = credentials(config, approval_for(config), prompt_passwords=True)\n"
            "assert value['service-provider']['password'] == 'SYNTHETIC_PTY_PASSWORD'\n"
            "print('PRIVATE_INPUT_ACCEPTED')\n"
        )
        environment = dict(os.environ, **self.emails)
        environment.pop("DTAP_QA_PASSWORD", None)
        environment["PYTHONPATH"] = str(Path(__file__).parent)
        process = subprocess.Popen(
            [sys.executable, "-c", code], stdin=slave, stdout=slave, stderr=slave,
            env=environment, start_new_session=True,
        )
        try:
            captured = b""
            sent = False
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        data = os.read(master, 4096)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    captured += data
                    if b"input hidden" in captured and not sent:
                        self.assertFalse(termios.tcgetattr(slave)[3] & termios.ECHO)
                        os.write(master, b"SYNTHETIC_PTY_PASSWORD\n")
                        sent = True
                if b"PRIVATE_INPUT_ACCEPTED" in captured:
                    break
            self.assertTrue(sent, "Hidden terminal prompt was not reached")
            self.assertEqual(process.wait(timeout=3), 0)
            self.assertIn(b"PRIVATE_INPUT_ACCEPTED", captured)
            self.assertNotIn(b"SYNTHETIC_PTY_PASSWORD", captured)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            os.close(master)
            os.close(slave)


class DoctorTests(unittest.TestCase):
    def test_html_needs_no_external_tools_or_browser(self):
        with patch("socket.socket", side_effect=AssertionError("Unexpected network")), patch(
            "vaptkit.doctor.shutil.which", return_value=None
        ) as lookup, patch("vaptkit.doctor.browser_check") as browser:
            value = diagnose("html")
        self.assertTrue(value["ready"])
        lookup.assert_not_called()
        browser.assert_not_called()

    def test_pdf_browser_failure_is_explicit(self):
        with patch("vaptkit.doctor.browser_check", return_value=(False, "Install Chromium.")):
            value = diagnose("pdf")
        self.assertFalse(value["ready"])
        self.assertEqual(value["checks"][-1]["detail"], "Install Chromium.")

    def test_role_config_selects_keyless_not_browser(self):
        config = configuration()
        config["access"] = {"type": "iap-service-account"}
        with patch("vaptkit.doctor.shutil.which", return_value=None) as lookup, patch(
            "vaptkit.doctor.browser_check"
        ) as browser:
            value = diagnose("roles", config)
        self.assertFalse(value["ready"])
        lookup.assert_called_once_with("gcloud")
        browser.assert_not_called()

    def test_headed_browser_requires_display(self):
        with patch.dict(os.environ, {}, clear=True), patch("vaptkit.doctor.sys.platform", "linux"), patch(
            "vaptkit.doctor.browser_check"
        ) as browser:
            value = diagnose("iap-browser")
        self.assertFalse(value["ready"])
        browser.assert_not_called()

    def test_cli_profile_and_config_validation(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(["doctor", "--for", "html"]), 0)
        self.assertTrue(json.loads(stdout.getvalue())["ready"])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["doctor", "--config", "missing.yml"]), 2)

    def test_push_checks_only_required_executable_names(self):
        with patch("vaptkit.doctor.shutil.which", return_value="/fixture/tool") as lookup:
            value = diagnose("push")
        self.assertTrue(value["ready"])
        self.assertEqual([call.args[0] for call in lookup.call_args_list], ["git", "docker"])
        self.assertTrue(any("not checked" in note for note in value["notes"]))


class SummaryTests(unittest.TestCase):
    def test_cli_prompt_wiring_and_sanitized_role_summary(self):
        config = configuration()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config.yml").write_text(yaml.safe_dump(config))
            (root / "approval.json").write_text(json.dumps(approval_for(config)))
            emails = {key: value for key, value in ENV.items() if key != "DTAP_QA_PASSWORD"}
            with patch.dict(os.environ, emails, clear=True), patch(
                "vaptkit.roles.sys.stdin.isatty", return_value=True
            ), patch("vaptkit.roles.getpass.getpass", return_value="SYNTHETIC_HIDDEN"), patch(
                "vaptkit.roles.request", side_effect=Application()
            ), patch("vaptkit.roles.time.sleep"), contextlib.redirect_stdout(io.StringIO()) as stdout:
                code = main(["roles", str(root / "config.yml"), "--approval", str(root / "approval.json"),
                             "--output", str(root / "out"), "--acknowledge-scope", "--prompt-passwords"])
            self.assertEqual(code, 0)
            text = stdout.getvalue()
            self.assertIn("3/3 tested, 0 blocked, 0 inconclusive, 0 not run", text)
            self.assertIn("2 acknowledged, 0 unconfirmed", text)
            self.assertIn("HTML/PDF report: not generated", text)
            self.assertIn(str(root / "out/assessment.json"), text)
            for secret in (*ENV.values(), "SYNTHETIC_HIDDEN"):
                self.assertNotIn(secret, text + (root / "out/assessment.json").read_text())

    def test_blocked_matrix_reports_cleanup_and_missing_cells(self):
        app = Application()
        def request(host, method, path, **kwargs):
            if method == "GET" and kwargs["headers"].get("Cookie"):
                return 302, {}, b""
            return app(host, method, path, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, ENV), patch(
            "vaptkit.roles.request", side_effect=request
        ), patch("vaptkit.roles.time.sleep"):
            config = configuration()
            path, code = run(config, approval_for(config), Path(directory) / "out")
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                print_assessment_summary(path)
        self.assertEqual(code, 1)
        self.assertIn("1/3 tested, 1 blocked, 0 inconclusive, 1 not run", stdout.getvalue())
        self.assertIn("Manual session cleanup may be required", stdout.getvalue())

    def test_header_summary_does_not_claim_application_coverage(self):
        from vaptkit.assessment import assess
        config = configuration()
        with tempfile.TemporaryDirectory() as directory, patch(
            "vaptkit.assessment.observe", return_value=observation(protected=True)
        ):
            path, code = assess(config, approved(config), Path(directory) / "out")
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                print_assessment_summary(path)
        self.assertEqual(code, 0)
        self.assertIn("1/1 successful responses", stdout.getvalue())
        self.assertIn("Unauthorized-access coverage: not_tested", stdout.getvalue())
