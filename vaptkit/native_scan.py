"""Native (no-Docker) Nuclei/ZAP fallback for local attack testing.

Only used when Docker isn't available. Native Nuclei is a direct equivalent of the
Docker path: same binary, same flags, same fixed-port-template exclusion logic (just
reimplemented in Python instead of shell, since find/xargs/grep aren't available on
plain Windows). Native ZAP instead drives ZAP's own "Automation Framework"
(`zap.sh/zap.cmd -cmd -autorun plan.yaml`) - the headless CLI mode ZAP itself
documents - since the Docker image's zap-full-scan.py script is not part of a normal
ZAP install.

Neither path has been exercised against a real installed copy of Nuclei or ZAP in
this kit's own test environment (no such environment is available here) - treat this
as logically-reviewed, not field-verified, until it's been run once for real.
"""
import re
import shutil
from pathlib import Path

from .process import stream
from .yamlutil import safe_dump

NUCLEI_CANDIDATES = ("nuclei",)
ZAP_CANDIDATES = ("zap.sh", "zap.cmd", "zap.bat", "zap")

# Same host-networking concern as the Docker path's NUCLEI_SCRIPT: a template that hardcodes
# its own port would probe other services on this machine instead of just the intended target.
FIXED_PORT_PATTERN = re.compile(r"\{\{(BaseURL|RootURL|Host|Hostname)\}\}:[0-9]{2,5}")


def nuclei_binary() -> str | None:
    return next((name for name in NUCLEI_CANDIDATES if shutil.which(name)), None)


def zap_binary() -> str | None:
    return next((name for name in ZAP_CANDIDATES if shutil.which(name)), None)


def nuclei_templates_dir() -> Path:
    """Nuclei's default template install location; unchanged across versions unless the user
    has set NUCLEI_TEMPLATES_DIR or passed -update-template-dir themselves, which this doesn't
    detect - worst case the fixed-port exclusion below just finds nothing, it doesn't fail."""
    return Path.home() / "nuclei-templates"


def fixed_port_templates(templates_dir: Path) -> list[str]:
    if not templates_dir.is_dir():
        return []
    matches = []
    for path in templates_dir.rglob("*.yaml"):
        try:
            if FIXED_PORT_PATTERN.search(path.read_text(errors="ignore")):
                matches.append(str(path))
        except OSError:
            continue
    return matches


def run_nuclei_native(binary: str, target: str, output: Path, printer, *, timeout: int,
                      on_timeout) -> tuple[str, int, bool]:
    stream([binary, "-update-templates", "-silent"], lambda line: None, timeout=120)
    excluded = fixed_port_templates(nuclei_templates_dir())
    command = [binary, "-u", target, "-pt", "http",
              "-severity", "low,medium,high,critical", "-c", "10", "-o", str(output / "nuclei.txt")]
    if excluded:
        exclude_file = output / "fixed-port-templates.txt"
        exclude_file.write_text("\n".join(excluded))
        command += ["-exclude-templates", str(exclude_file)]
    return stream(command, printer, timeout=timeout, on_timeout=on_timeout)


def run_zap_native(binary: str, target: str, output: Path, printer, *, timeout: int,
                   on_timeout) -> tuple[str, int, bool]:
    plan = {
        "env": {
            "contexts": [{"name": "target", "urls": [target]}],
            "parameters": {"progressToStdout": True},
        },
        "jobs": [
            {"type": "spider", "parameters": {"context": "target", "url": target}},
            {"type": "activeScan", "parameters": {"context": "target"}},
            {"type": "report", "parameters": {
                "template": "traditional-html", "reportDir": str(output),
                "reportFile": "zap-report", "reportTitle": "ZAP Scan Report",
            }},
        ],
    }
    plan_path = output / "zap-plan.yaml"
    plan_path.write_text(safe_dump(plan))
    return stream([binary, "-cmd", "-autorun", str(plan_path)], printer, timeout=timeout, on_timeout=on_timeout)
