"""Pure-Python YAML load/dump, used instead of PyYAML directly.

ruamel.yaml's safe mode never needs a compiled C extension to install or run
(unlike PyYAML, whose wheel coverage lags behind new Python releases), so
nothing here should ever require a compiler on the user's machine.
"""
import io

from ruamel.yaml import YAML, YAMLError  # noqa: F401 (re-exported for callers)


def safe_load(text: str):
    return YAML(typ="safe").load(text)


def safe_dump(data, *, sort_keys: bool = True) -> str:
    yaml = YAML(typ="safe")
    yaml.default_flow_style = False
    yaml.sort_base_mapping_type_on_output = sort_keys
    stream = io.StringIO()
    yaml.dump(data, stream)
    return stream.getvalue()
