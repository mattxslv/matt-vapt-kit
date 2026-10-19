import json
import re
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from ruamel.yaml import YAML, YAMLError
from ruamel.yaml.composer import Composer
from ruamel.yaml.constructor import SafeConstructor
from ruamel.yaml.events import AliasEvent

MAX_CONFIG_BYTES = 65536


class ConfigError(ValueError):
    pass


class _NoAliasComposer(Composer):
    def compose_node(self, parent, index):
        if self.parser.check_event(AliasEvent):
            raise ConfigError("YAML aliases are not allowed.")
        return super().compose_node(parent, index)


class _StrictConstructor(SafeConstructor):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConfigError("Configuration keys must be strings.")
            if key in result:
                raise ConfigError("Duplicate configuration keys are not allowed.")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _yaml_loader() -> YAML:
    loader = YAML(typ="safe")
    loader.Composer = _NoAliasComposer
    loader.Constructor = _StrictConstructor
    return loader


def load_config(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ConfigError("Cannot read the configuration file.") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("Configuration exceeds the 64 KiB limit.")
    try:
        config = _yaml_loader().load(raw.decode("utf-8"))
    except (UnicodeError, YAMLError, RecursionError):
        # Parser messages can echo credentials accidentally pasted into YAML.
        raise ConfigError("Invalid YAML configuration; values have been withheld.") from None

    schema = json.loads(files("vaptkit").joinpath("schemas/project.json").read_text())
    error = next(Draft202012Validator(schema).iter_errors(config), None)
    if error is not None:
        raise ConfigError(
            f"Configuration does not match the project schema ({error.validator}); "
            "values have been withheld."
        )

    target = config["target"]
    url = target["url"]
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ConfigError("Invalid target URL.") from None
    if (
        any(character.isspace() or ord(character) < 32 for character in url)
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname not in target["allowed_hosts"]
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or "?" in url
        or "#" in url
        or parsed.netloc not in (parsed.hostname, f"{parsed.hostname}:443")
    ):
        raise ConfigError("Target must be an exact allowlisted HTTPS origin on port 443.")

    for prefix in config["scope"]["api_prefixes"] + config["scope"]["excluded_prefixes"]:
        if (
            prefix.startswith("//")
            or any(char in prefix for char in ("\\", "?", "#", "%"))
            or any(char.isspace() or ord(char) < 32 for char in prefix)
            or any(part in (".", "..") for part in prefix.split("/"))
        ):
            raise ConfigError("Scope prefixes must be literal, normalized URL paths.")
    for pattern in config.get("review", {}).get("auth_patterns", []) + config.get("review", {}).get("role_patterns", []):
        try:
            re.compile(pattern)
        except re.error:
            raise ConfigError("Review patterns must be valid regular expressions.") from None
    if not set(config["credentials"]).issubset(config["scope"]["roles"]):
        raise ConfigError("Credential roles must appear in scope.roles.")
    if config.get("access", {}).get("type") == "bearer" and not re.fullmatch(r"[A-Z][A-Z0-9_]*", config["access"]["token_env"]):
        raise ConfigError("Access token configuration must name an environment variable.")
    if "role_testing" in config:
        settings = config["role_testing"]
        ids = [item["id"] for item in settings["accounts"]]
        paths = [item["path"] for item in settings["routes"]]
        if len(set(ids)) != len(ids) or "anonymous" in ids or len(set(paths)) != len(paths):
            raise ConfigError("Role account IDs and route paths must be unique; anonymous is reserved.")
        roles = set(config["scope"]["roles"])
        if any(item["role"] not in roles for item in settings["accounts"]) or any(
                not set(item["allowed_roles"]) <= roles for item in settings["routes"]):
            raise ConfigError("Role matrix roles must appear in scope.roles.")
        for path in paths:
            if (not path.startswith("/api/") or path.startswith("/api/auth/")
                    or any(char.isspace() or not 33 <= ord(char) <= 126 for char in path)
                    or any(char in path for char in ("?", "#", "%", "\\"))
                    or any(part in (".", "..") for part in path.split("/"))
                    or any(path.startswith(prefix) for prefix in config["scope"]["excluded_prefixes"])):
                raise ConfigError("Role routes must be exact, non-auth API paths inside the approved scope.")
    return config
