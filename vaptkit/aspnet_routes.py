"""Offline review of ASP.NET controller and minimal-API authorization in committed C# source.

Understands [Authorize]/[AllowAnonymous] (including custom *Authorize* attributes and attributes
inherited from base controllers), global authorize filters, fallback policies, and
RequireAuthorization() on minimal APIs and route groups. WebForms pages are not covered.
"""
import re

HTTP_VERBS = {"HttpGet": "GET", "HttpPost": "POST", "HttpPut": "PUT", "HttpPatch": "PATCH", "HttpDelete": "DELETE"}
MAP_VERBS = {"MapGet": "GET", "MapPost": "POST", "MapPut": "PUT", "MapPatch": "PATCH", "MapDelete": "DELETE"}
GLOBAL_AUTH = re.compile(
    r"[Ff]ilters\s*\.\s*Add\s*\(\s*new\s+\w*Authorize\w*|FallbackPolicy\s*=|MapControllers\s*\(\s*\)\s*\.\s*RequireAuthorization"
)
CLASS = re.compile(r"\bclass\s+(\w+)\s*(?:<[^>{]*>)?\s*(?::\s*([^{]+))?\{")
METHOD = re.compile(
    r"\bpublic\s+(?:(?:async|virtual|override|static|new|sealed)\s+)*[\w<>\[\],.?\s]+?\s+(\w+)\s*(?:<[^>(]*>)?\s*\("
)
ATTRIBUTE = re.compile(r"(\w+?)(?:Attribute)?\s*(?:\(([^()]*(?:\([^()]*\)[^()]*)*)\))?\s*(?:,|$)")
TEMPLATE = re.compile(r'^\s*@?"([^"]*)"')
MAP_CALL = re.compile(r"\b(\w+)\s*\.\s*(MapGet|MapPost|MapPut|MapPatch|MapDelete)\s*\(\s*@?\"([^\"]*)\"")
BODY_AUTHN = re.compile(r"\.IsAuthenticated\b|IsInRole\s*\(|AuthorizeAsync\s*\(|\bAuthorize\s*\(|"
                        r"\w*[Pp]ermission\w*\s*\.\s*\w*Authorize\w*\s*\(|HasPermission\w*\s*\(")
BODY_AUTHZ = re.compile(r"IsInRole\s*\(|AuthorizeAsync\s*\(|[Pp]ermission")
GROUP = re.compile(r"\b(?:var\s+)?(\w+)\s*=\s*(\w+)\s*\.\s*MapGroup\s*\(\s*@?\"([^\"]*)\"\s*\)([^;]*);")


def mask_strings(source: str) -> str:
    """Blank string contents (keeping quotes and offsets) so braces in route templates don't skew nesting."""
    out, i, n = list(source), 0, len(source)
    while i < n:
        if source[i] == '"':
            verbatim = i > 0 and source[i - 1] == "@"
            j = i + 1
            while j < n:
                if verbatim and source[j] == '"' and j + 1 < n and source[j + 1] == '"':
                    j += 2
                    continue
                if not verbatim and source[j] == "\\":
                    j += 2
                    continue
                if source[j] == '"':
                    break
                j += 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def statement_end(masked: str, start: int) -> int:
    """Index of the ';' ending the statement that starts at `start`, skipping lambda bodies and arguments."""
    depth = 0
    for index in range(start, len(masked)):
        char = masked[index]
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
        elif char == ";" and depth <= 0:
            return index
    return len(masked)


def method_body(masked: str, signature_end: int) -> str:
    """Text of a method body (block or expression-bodied) whose parameter list opens just before signature_end."""
    depth, index = 1, signature_end
    while index < len(masked) and depth:
        depth += {"(": 1, ")": -1}.get(masked[index], 0)
        index += 1
    rest = masked[index:index + 400]
    arrow, block = rest.find("=>"), rest.find("{")
    if block >= 0 and (arrow < 0 or block < arrow) and ";" not in rest[:block]:
        start = index + block
        return masked[start:matching_brace(masked, start) + 1]
    return masked[index:statement_end(masked, index)] if arrow >= 0 else ""


def matching_brace(masked: str, start: int) -> int:
    depth = 0
    for index in range(start, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(masked) - 1


def attributes_before(source: str, masked: str, position: int) -> list[tuple[str, str]]:
    """[(name, arguments)] for the attribute lists directly above a declaration."""
    found, end = [], position
    while True:
        prefix = masked[:end].rstrip()
        prefix = re.sub(r"(?:\b(?:public|internal|protected|private|sealed|abstract|partial|static|async|virtual|override|new)\s*)+$",
                        "", prefix).rstrip()
        if not prefix.endswith("]"):
            return found
        depth, index = 0, len(prefix) - 1
        while index >= 0:
            if prefix[index] == "]":
                depth += 1
            elif prefix[index] == "[":
                depth -= 1
                if depth == 0:
                    break
            index -= 1
        inner = source[index + 1:len(prefix) - 1]
        for name, args in ATTRIBUTE.findall(inner.strip()):
            found.append((name, args or ""))
        end = index


def template(args: str) -> str | None:
    match = TEMPLATE.match(args)
    return match[1] if match else None


def join_route(prefix: str | None, action: str | None, controller: str, method_name: str) -> str:
    if action is not None and action.startswith(("/", "~/")):
        path = action.lstrip("~")
    elif prefix is None and action is None:
        path = f"/{controller}/{method_name}"
    else:
        path = "/" + "/".join(part.strip("/") for part in (prefix, action) if part)
    path = path.replace("[controller]", controller).replace("[action]", method_name).replace("[area]", "{area}")
    return re.sub(r"/+", "/", path) or "/"


def auth_flags(attributes: list[tuple[str, str]], extra_auth: re.Pattern | None) -> tuple[bool, bool, bool]:
    """(authenticated, has role/policy check, explicitly anonymous) from one attribute list."""
    authenticated = any("authorize" in name.lower() or (extra_auth and extra_auth.search(name))
                        for name, _ in attributes)
    roles = any(("authorize" in name.lower() or (extra_auth and extra_auth.search(name)))
                and re.search(r"\b(Roles|Policy)\s*=|^\s*\"", args) for name, args in attributes)
    roles = roles or any(name.lower() != "authorize" and "authorize" in name.lower() for name, _ in attributes)
    anonymous = any(name == "AllowAnonymous" for name, _ in attributes)
    return authenticated, roles, anonymous


def review_aspnet(read, files: set[str], *, auth_attributes: list[str] | None = None) -> list[dict]:
    """Routes in the shared route-review shape: {path, file, handlers: [{method, authentication, ...}]}."""
    extra = re.compile("|".join(auth_attributes)) if auth_attributes else None
    sources = {path: read(path) for path in sorted(files)
               if path.endswith(".cs") and not re.search(r"(^|/)(tests?|[^/]*\.Tests?)/", path, re.IGNORECASE)}
    global_auth = any(GLOBAL_AUTH.search(source) for source in sources.values())

    classes = {}
    for path, source in sources.items():
        masked = mask_strings(source)
        for match in CLASS.finditer(masked):
            body_start = match.end() - 1
            classes[match[1]] = {
                "file": path, "source": source, "masked": masked, "start": body_start,
                "end": matching_brace(masked, body_start),
                "base": (match[2] or "").split(",")[0].strip().split("<")[0].split(".")[-1],
                "attributes": attributes_before(source, masked, match.start()),
            }

    def inherited(name: str, seen=()) -> list[tuple[str, str]]:
        info = classes.get(name)
        if not info or name in seen:
            return []
        return info["attributes"] + inherited(info["base"], seen + (name,))

    def is_controller(name: str, seen=()) -> bool:
        info = classes.get(name)
        if name in ("Controller", "ControllerBase", "ApiController") or name.endswith("Controller") and not info:
            return True
        return bool(info) and name not in seen and (name.endswith("Controller") or is_controller(info["base"], seen + (name,)))

    routes = []
    for name, info in classes.items():
        if not name.endswith("Controller") or not is_controller(name):
            continue
        class_attributes = inherited(name)
        if any(attr == "NonController" for attr, _ in class_attributes):
            continue
        prefix = next((template(args) for attr, args in class_attributes if attr == "Route" and template(args) is not None), None)
        controller = name.removesuffix("Controller")
        body = info["masked"]
        for method in METHOD.finditer(body, info["start"], info["end"]):
            depth = body[info["start"]:method.start()].count("{") - body[info["start"]:method.start()].count("}")
            if depth != 1 or method[1] == name:
                continue
            action_attributes = attributes_before(info["source"], body, method.start())
            if any(attr == "NonAction" for attr, _ in action_attributes):
                continue
            verbs = [(HTTP_VERBS[attr], template(args)) for attr, args in action_attributes if attr in HTTP_VERBS]
            route_template = next((template(args) for attr, args in action_attributes if attr == "Route"), None)
            class_auth, class_roles, class_anon = auth_flags(class_attributes, extra)
            action_auth, action_roles, action_anon = auth_flags(action_attributes, extra)
            body_text = method_body(body, method.end())
            body_auth, body_roles = bool(BODY_AUTHN.search(body_text)), bool(BODY_AUTHZ.search(body_text))
            authenticated = class_auth or action_auth or body_auth or global_auth
            for verb, verb_template in verbs or [("ANY", None)]:
                path = join_route(prefix, verb_template if verb_template is not None else route_template,
                                  controller, method[1])
                routes.append({"path": path, "file": info["file"], "handlers": [{
                    "method": verb, "authentication": authenticated,
                    "authorization": class_roles or action_roles or body_roles,
                    "public": class_anon or action_anon, "stub": False,
                }]})

    for path, source in sources.items():
        masked = mask_strings(source)
        groups = {}
        for group in GROUP.finditer(source):
            parent = groups.get(group[2], ("", False))
            groups[group[1]] = (parent[0] + "/" + group[3].strip("/"), parent[1] or "RequireAuthorization" in group[4])
        for call in MAP_CALL.finditer(source):
            chain = masked[call.end():statement_end(masked, call.start())]
            group_prefix, group_auth = groups.get(call[1], ("", False))
            lambda_attributes = re.findall(r"\[\s*(\w+)\s*(\([^\]]*\))?\s*\]", source[call.end():call.end() + len(chain)])
            lambda_auth = any("authorize" in name.lower() for name, _ in lambda_attributes)
            lambda_roles = any("authorize" in name.lower() and re.search(r"Roles|Policy", args) for name, args in lambda_attributes)
            routes.append({"path": re.sub(r"/+", "/", "/" + group_prefix.strip("/") + "/" + call[3].strip("/")).rstrip("/") or "/",
                           "file": path, "handlers": [{
                               "method": MAP_VERBS[call[2]],
                               "authentication": group_auth or global_auth or lambda_auth or "RequireAuthorization" in chain,
                               "authorization": lambda_roles or bool(re.search(r"RequireAuthorization\s*\(\s*[^)\s]", chain)),
                               "public": "AllowAnonymous" in chain, "stub": False,
                           }]})
    return routes
