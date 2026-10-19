import copy
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vaptkit.yamlutil import safe_dump, safe_load

from vaptkit.cli import CORE_TOOLS, main
from vaptkit.config import ConfigError, MAX_CONFIG_BYTES, load_config

ROOT = Path(__file__).resolve().parents[1]


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "config.yml"
        self.config = safe_load((ROOT / "projects/pemedes.vapt.yml").read_text())

    def write(self, config=None):
        self.path.write_text(safe_dump(self.config if config is None else config))
        return self.path

    def test_project_configs(self):
        for path in sorted((ROOT / "projects").glob("*.vapt.yml")):
            with self.subTest(path=path):
                self.assertEqual(load_config(path)["target"]["environment"], "staging")

    def test_starter_template_is_valid_and_nonlive(self):
        path = ROOT / "templates/project.example.yml"
        with patch("socket.socket", side_effect=AssertionError("Unexpected network request")):
            config = load_config(path)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["validate", str(path)]), 0)
        self.assertEqual(config["target"]["url"], "https://staging.example.invalid")
        self.assertEqual(config["target"]["verification"], "pending")
        self.assertNotIn("access", config)
        self.assertNotIn("role_testing", config)
        self.assertIn('"scan_authorized": false', output.getvalue())

    def test_invalid_targets(self):
        urls = [
            "http://staging.example.com", "https://other.example.com",
            "https://user:secret@staging.example.com",
            "https://staging.example.com:8443", "https://staging.example.com/api/",
            "https://staging.example.com?token=secret", "https://staging.example.com#fragment",
            "https://staging.example.com?", "https://staging.example.com#",
            "https://staging.example.com:bad", "https://staging.example.com\n",
            " https://staging.example.com", "https://STAGING.example.com",
            "https://staging.example.com:", "https://staging.example.com:0443",
        ]
        self.config["target"]["allowed_hosts"] = ["staging.example.com"]
        for url in urls:
            with self.subTest(url=url):
                self.config["target"]["url"] = url
                with self.assertRaises(ConfigError):
                    load_config(self.write())

    def test_https_origin_with_default_port(self):
        self.config["target"]["url"] += ":443/"
        self.assertEqual(load_config(self.write())["project"], "pemedes")

    def test_production_and_unknown_keys_rejected(self):
        for modify in (
            lambda c: c["target"].update(environment="production"),
            lambda c: c.update(unknown=True),
            lambda c: c["target"].update(verification="authorized"),
            lambda c: c.update(credentials={"admin": {"password": "PRIVATE_SENTINEL"}}),
            lambda c: c.update(credentials={"unknown": {"token_env": "TEST_TOKEN"}}),
            lambda c: c["target"].update(allowed_hosts=["*.example.com"]),
        ):
            with self.subTest(modify=modify):
                config = copy.deepcopy(self.config)
                modify(config)
                with self.assertRaises(ConfigError) as error:
                    load_config(self.write(config))
                self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))

    def test_env_names_only(self):
        self.config["credentials"] = {"admin": {"token_env": "VAPT_PEMEDES_ADMIN_TOKEN"}}
        self.assertEqual(load_config(self.write())["credentials"], self.config["credentials"])

    def test_role_matrix_config_validation(self):
        base = load_config(ROOT / "projects/dtap.vapt.yml")
        for change in (
            lambda c: c["role_testing"]["accounts"][0].update(id="anonymous"),
            lambda c: c["role_testing"]["accounts"][0].update(role="unknown"),
            lambda c: c["role_testing"]["accounts"].append(c["role_testing"]["accounts"][0]),
            lambda c: c["role_testing"]["routes"][0].update(path="/api/auth/signout"),
            lambda c: c["role_testing"]["routes"][0].update(path="/api/x?token=private"),
            lambda c: c["role_testing"]["routes"][0].update(path="/api/a/../admin"),
            lambda c: c["role_testing"]["routes"][0].update(allowed_roles=["unknown"]),
            lambda c: c["role_testing"]["routes"][0].update(response_shape={}),
            lambda c: c["role_testing"]["accounts"][0].update(password="PRIVATE_SENTINEL"),
        ):
            config = copy.deepcopy(base)
            change(config)
            with self.assertRaises(ConfigError):
                load_config(self.write(config))

    def test_access_config_is_explicit_and_environment_only(self):
        self.config["access"] = {"type": "bearer", "token_env": "VAPT_IAP_TOKEN", "header": "Proxy-Authorization"}
        self.assertEqual(load_config(self.write())["access"], self.config["access"])
        for changes in (
            {"token_env": "VAPT_IAP_TOKEN\n"}, {"header": "Cookie"},
            {"token": "PRIVATE_SENTINEL"}, {"type": "shell"},
        ):
            config = copy.deepcopy(self.config)
            config["access"].update(changes)
            with self.assertRaises(ConfigError) as error:
                load_config(self.write(config))
            self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))

    def test_keyless_access_config_requires_account_not_keys(self):
        self.config["access"] = {
            "type": "iap-service-account",
            "service_account": "fixture-pilot@fixture-project.iam.gserviceaccount.com",
        }
        self.assertEqual(load_config(self.write())["access"], self.config["access"])
        for changes in (
            {"service_account": "user@example.invalid"}, {"service_account": "../outside"},
            {"service_account": "fixture-pilot@fixture-project.iam.gserviceaccount.com\n"},
            {"key_file": "/private/key.json"}, {"token": "PRIVATE_SENTINEL"},
        ):
            config = copy.deepcopy(self.config)
            config["access"].update(changes)
            with self.assertRaises(ConfigError):
                load_config(self.write(config))

    def test_invalid_paths(self):
        for prefix in ("//elsewhere", "/api/../admin", "/%2e%2e/", "/api?token=x",
                       "/api#fragment", "/api\\admin", "/api\n"):
            with self.subTest(prefix=prefix):
                self.config["scope"]["excluded_prefixes"] = [prefix]
                with self.assertRaises(ConfigError):
                    load_config(self.write())

    def test_invalid_yaml_and_sensitive_values(self):
        for text in (
            "project: one\nproject: two", "project: &a test\nscope: *a",
            "project: [PRIVATE_SENTINEL", "null", "- item", "1: value",
            "!!python/object:builtins.object {}", "PRIVATE_SENTINEL: unexpected",
        ):
            with self.subTest(text=text):
                self.path.write_text(text)
                with self.assertRaises(ConfigError) as error:
                    load_config(self.path)
                self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))

    def test_file_errors_and_size_limit(self):
        with self.assertRaises(ConfigError):
            load_config(self.path)
        self.path.write_bytes(b"x" * (MAX_CONFIG_BYTES + 1))
        with self.assertRaises(ConfigError):
            load_config(self.path)
        self.path.write_bytes(b"\xff")
        with self.assertRaises(ConfigError):
            load_config(self.path)

    def test_cli_offline_validation(self):
        with patch("socket.socket", side_effect=AssertionError("Unexpected network request")):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["validate", str(self.write())]), 0)
        self.assertIn('"scan_authorized": false', output.getvalue())

    def test_cli_failure(self):
        with contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(main(["validate", str(self.path)]), 2)
        self.assertIn("Configuration error:", output.getvalue())

    def test_doctor_reports_missing_tools(self):
        for available in (True, False):
            with patch("shutil.which", return_value="/bin/tool" if available else None):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(["doctor"]), 0 if available else 1)
                for tool in CORE_TOOLS:
                    self.assertIn(tool, output.getvalue())


if __name__ == "__main__":
    unittest.main()
