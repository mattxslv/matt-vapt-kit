"""Offline white-box review of Next.js and ASP.NET API route authentication.

Reads one committed revision through git (the working tree is never touched) and
follows calls from each exported handler into local and imported helpers to
decide whether an authentication and an authorization check is reachable.
Results are "suspected" until confirmed by an approved live test.
"""
import json
import posixpath
import re
from datetime import datetime, timezone
from pathlib import Path

from .aspnet_routes import review_aspnet
from .checks import checked_revision
from .process import ToolError, git

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs")
ROUTE_FILE = re.compile(r"^(?:src/)?app/(.*/)?route\.(?:ts|tsx|js|jsx|mjs)$")
PAGES_API = re.compile(r"^(?:src/)?pages/(api/.*)\.(?:ts|tsx|js|jsx)$")
DEFAULT_AUTHN = (
    r"(?:verify|validate)\w*(?:Token|Session|Jwt|JWT|Signature)\s*\(|is\w*(?:Session|Token)\w*Valid\s*\("
    r"|timingSafeEqual|(?:!==|===)\s*`Bearer\s*\$\{"
    r"|(?:!==|===)\s*process\.env\.\w*(?:SECRET|TOKEN|KEY)|process\.env\.\w*(?:SECRET|TOKEN|KEY)\w*\s*(?:!==|===)"
    r"|verifyToken|jwtVerify|jwt\.verify|getServerSession|getToken\s*\(|\bauth\s*\(\s*\)|currentUser\s*\("
    r"|verifyIdToken|verifySessionCookie|validateSession|verifySession|auth\.getUser|requireAuth|getAuth\s*\("
)
DEFAULT_AUTHZ = (
    r"user_type|userType|\.role\b|\broles?\b|isAdmin|requireRole|hasRole|hasPermission|can[A-Z]\w*\s*\("
    r"|owner|user_id\s*[!=]==|status\s*:\s*403|Forbidden"
)
CALL = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>)?\s*\(")
MEMBER_CALL = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(")
IMPORT = re.compile(r"import\s+(?:type\s+)?([\s\S]*?)\s+from\s+['\"]([^'\"]+)['\"]")
BINDING = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:await\s+)?(?:new\s+)?([A-Za-z_$][\w$]*)\s*\(")
KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "typeof", "await", "new", "super"}


def strip_comments(source: str) -> str:
    out, i, n = [], 0, len(source)
    while i < n:
        char = source[i]
        if char in "'\"`":
            end = i + 1
            while end < n and source[end] != char:
                end += 2 if source[end] == "\\" else 1
            out.append(source[i:end + 1])
            i = end + 1
        elif source.startswith("//", i):
            end = source.find("\n", i)
            i = n if end < 0 else end
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


def matching(source: str, start: int, open_char: str, close_char: str) -> int:
    depth = 0
    for index in range(start, len(source)):
        if source[index] == open_char:
            depth += 1
        elif source[index] == close_char:
            depth -= 1
            if depth == 0:
                return index
    return len(source) - 1


def function_body(source: str, name: str) -> str | None:
    escaped = re.escape(name)
    pattern = re.compile(
        rf"(?:function\s*\*?\s*{escaped}\s*(?:<[^>]*>)?\s*\(|(?:const|let|var)\s+{escaped}\s*(?::[^=]+)?=\s*)"
        rf"|(?:^|\n)\s*(?:static\s+)?(?:async\s+)?{escaped}\s*\("
    )
    match = pattern.search(source)
    if not match:
        return None
    position = match.end()
    if source[position - 1] == "(":
        position = skip_return_type(source, matching(source, position - 1, "(", ")") + 1)
    brace = source.find("{", position)
    newline = source.find("\n", position)
    arrow_expression = "=>" in source[position:newline if newline > 0 else None] and (
        brace < 0 or (newline > 0 and brace > newline)
    )
    if brace < 0 or arrow_expression:
        end = source.find(";", position)
        return source[match.start():end if end > 0 else len(source)]
    return source[match.start():matching(source, brace, "{", "}") + 1]


def skip_return_type(source: str, position: int) -> int:
    """Skip a TypeScript return type such as `: Promise<{ user: User }>` after a parameter list."""
    index = position
    while index < len(source) and source[index].isspace():
        index += 1
    if index >= len(source) or source[index] != ":":
        return position
    depth, index, previous = 0, index + 1, ":"
    while index < len(source):
        char = source[index]
        if source.startswith("=>", index) and depth == 0:
            return index
        if char in "<([":
            depth += 1
        elif char in ">)]" and depth:
            depth -= 1
        elif char == "{":
            if depth == 0 and previous not in ":|&,<(":
                return index
            index = matching(source, index, "{", "}")
        if not char.isspace():
            previous = source[index] if char != "{" else "}"
        index += 1
    return index


class Tree:
    def __init__(self, repo: Path, sha: str):
        self.repo, self.sha = repo, sha
        self.files = set(git(repo, "ls-tree", "-r", "--name-only", sha).splitlines())
        self.cache: dict[str, str] = {}
        self.aliases = self._aliases()

    def read(self, path: str) -> str:
        if path not in self.cache:
            try:
                self.cache[path] = strip_comments(git(self.repo, "show", f"{self.sha}:{path}"))
            except ToolError:
                self.cache[path] = ""
        return self.cache[path]

    def _aliases(self) -> list[tuple[str, str]]:
        for name in ("tsconfig.json", "jsconfig.json"):
            if name in self.files:
                try:
                    raw = re.sub(r",\s*([}\]])", r"\1", self.read(name))
                    paths = json.loads(raw).get("compilerOptions", {}).get("paths", {})
                except ValueError:
                    continue
                return [
                    (key[:-1], posixpath.normpath(targets[0][:-1].lstrip("./")) + "/" if targets[0][:-1].strip("./") else "")
                    for key, targets in paths.items() if key.endswith("*") and targets and targets[0].endswith("*")
                ]
        return [("@/", "")]

    def resolve(self, importer: str, spec: str) -> str | None:
        if spec.startswith("."):
            base = posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))
        else:
            base = next((target + spec[len(prefix):] for prefix, target in self.aliases if spec.startswith(prefix)), None)
            if base is None:
                return None
        for candidate in [base, *(base + ext for ext in EXTENSIONS), *(f"{base}/index{ext}" for ext in EXTENSIONS)]:
            if candidate in self.files:
                return candidate
        return None


def imports(source: str) -> dict[str, tuple[str, str]]:
    """Map local identifier -> (module spec, exported name)."""
    result = {}
    for clause, spec in IMPORT.findall(source):
        clause = clause.strip()
        named = re.search(r"\{([\s\S]*)\}", clause)
        if named:
            for part in named.group(1).split(","):
                pieces = part.replace("type ", "").split(" as ")
                if pieces[0].strip():
                    result[pieces[-1].strip()] = (spec, pieces[0].strip())
        default = re.match(r"([A-Za-z_$][\w$]*)", clause)
        if default and not clause.startswith("{"):
            result[default.group(1)] = (spec, "default")
        namespace = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", clause)
        if namespace:
            result[namespace.group(1)] = (spec, "*")
    for clause, spec in re.findall(r"(?:const|let|var)\s*(\{[^}]*\})\s*=\s*await\s+import\(\s*['\"]([^'\"]+)['\"]\s*\)", source):
        for part in clause.strip("{} ").split(","):
            pieces = [piece.strip() for piece in part.split(":")]
            if pieces[0]:
                result[pieces[-1]] = (spec, pieces[0])
    return result


class Analyzer:
    def __init__(self, tree: Tree, authn: str, authz: str):
        self.tree = tree
        self.authn, self.authz = re.compile(authn), re.compile(authz)
        self.memo: dict[tuple[str, str], tuple[bool, bool]] = {}

    def factory_module(self, file: str, symbol: str) -> str:
        """Module that defines the object a factory returns: follow one `return new X(...)` hop."""
        body = function_body(self.tree.read(file), symbol) or ""
        created = re.search(r"new\s+([A-Za-z_$][\w$]*)\s*\(", body)
        if created:
            spec = imports(self.tree.read(file)).get(created.group(1))
            if spec:
                return self.tree.resolve(file, spec[0]) or file
        return file

    def _is_class(self, file: str, name: str) -> bool:
        return bool(re.search(rf"class\s+{re.escape(name)}\b", self.tree.read(file)))

    def callees(self, file: str, body: str) -> list[tuple[str, str]]:
        source = self.tree.read(file)
        imported = imports(source)
        result = []
        for name in CALL.findall(body):
            if name in KEYWORDS:
                continue
            if name in imported:
                spec, exported = imported[name]
                target = self.tree.resolve(file, spec)
                if target:
                    result.append((target, exported))
            elif function_body(source, name) is not None:
                result.append((file, name))
        bindings = {}
        for variable, factory in BINDING.findall(body):
            if factory in imported:
                target = self.tree.resolve(file, imported[factory][0])
                if target:
                    bindings[variable] = self.factory_module(target, imported[factory][1])
        for obj, member in MEMBER_CALL.findall(body):
            if obj == "this" and function_body(source, member) is not None:
                result.append((file, member))
                continue
            if obj in bindings and obj not in imported:
                result.append((bindings[obj], member))
                continue
            if obj not in imported:
                continue
            spec, exported = imported[obj]
            target = self.tree.resolve(file, spec)
            if not target:
                continue
            if exported == "*":
                result.append((target, member))
            elif exported != "default" and self._is_class(target, exported):
                class_body = function_body(self.tree.read(target), exported) or ""
                result.append((target, member) if function_body(class_body, member) else (target, exported))
            else:
                result.append((target, exported))
        return list(dict.fromkeys(result))

    def body_signals(self, file: str, body: str, depth: int, seen: set) -> tuple[bool, bool]:
        authn, authz = bool(self.authn.search(body)), bool(self.authz.search(body))
        if (authn and authz) or depth >= 4:
            return authn, authz
        for key in self.callees(file, body):
            if key in seen:
                continue
            seen.add(key)
            child_n, child_z = self.symbol_signals(*key, depth + 1, seen)
            authn, authz = authn or child_n, authz or child_z
            if authn and authz:
                break
        return authn, authz

    def symbol_signals(self, file: str, symbol: str, depth: int, seen: set) -> tuple[bool, bool]:
        key = (file, symbol)
        if key in self.memo:
            return self.memo[key]
        source = self.tree.read(file)
        if symbol in ("default", "*"):
            body = re.search(r"export\s+default[\s\S]*", source)
            body = body.group(0) if body else source
        else:
            body = function_body(source, symbol)
            if body is None:
                class_match = re.search(rf"class\s+{re.escape(symbol)}\b", source)
                body = function_body(source, symbol) if not class_match else source[class_match.start():matching(source, source.find("{", class_match.end()), "{", "}") + 1]
            if body is None:
                specs = re.findall(rf"export\s*\{{[^}}]*\b{re.escape(symbol)}\b[^}}]*\}}\s*from\s*['\"]([^'\"]+)['\"]", source)
                specs += re.findall(r"export\s*\*\s*from\s*['\"]([^'\"]+)['\"]", source)
                for spec in specs:
                    target = self.tree.resolve(file, spec)
                    if target and (target, symbol) not in seen:
                        seen.add((target, symbol))
                        result = self.symbol_signals(target, symbol, depth, seen)
                        if result != (False, False):
                            self.memo[key] = result
                            return result
                self.memo[key] = (False, False)
                return self.memo[key]
        result = self.body_signals(file, body, depth, seen)
        self.memo[key] = result
        return result


def route_path(file: str) -> str:
    match = ROUTE_FILE.match(file)
    if match:
        parts = (match.group(1) or "").strip("/").split("/")
    else:
        parts = PAGES_API.match(file).group(1).split("/")
        if parts[-1] == "index":
            parts = parts[:-1]
    cleaned = []
    for part in parts:
        if not part or (part.startswith("(") and part.endswith(")")) or part.startswith("@"):
            continue
        part = re.sub(r"^\[\[?\.\.\.(.+?)\]?\]$", r"{\1*}", part)
        cleaned.append(re.sub(r"^\[(.+)\]$", r"{\1}", part))
    return "/" + "/".join(cleaned)


def handlers(source: str) -> dict[str, str]:
    """Map HTTP method -> handler source text."""
    found = {}
    for method in METHODS:
        if re.search(rf"export\s+(?:async\s+)?function\s+{method}\b|export\s+(?:const|let)\s+{method}\b", source):
            found[method] = function_body(source, method) or ""
            continue
        alias = re.search(rf"export\s*\{{[^}}]*?\b([A-Za-z_$][\w$]*)\s+as\s+{method}\b", source)
        if alias:
            found[method] = function_body(source, alias.group(1)) or alias.group(1) + "()"
    if not found and re.search(r"export\s+default\b", source):
        found["ANY"] = re.search(r"export\s+default[\s\S]*", source).group(0)
    return found


def is_stub(body: str) -> bool:
    """A handler that only returns a fixed response (or 404/405/410/501) exposes nothing."""
    if "process.env" in body or "request" in body.split("{", 1)[-1] or "req." in body:
        return False
    calls = {name for name in CALL.findall(body) if name not in KEYWORDS}
    calls -= {"json", "NextResponse", "Response", "error", "warn", "log", "routeParams", "params"}
    calls -= set(METHODS)
    return not calls and "await " not in re.sub(r"await\s+(?:routeParams|params|context\.params)", "", body)


MIDDLEWARE_FILES = ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js")
ROLE_RULE = re.compile(r"\[\s*/(\^\\/api(?:\\.|\[[^\]\n]*\]|[^/\\\n])*)/[a-z]*\s*,")
USER_ID_NAMES = r"(?:userId|user_id|employeeId|employee_id|staffId|accountId|account_id|ownerId|profileId)"
ID_FROM_REQUEST = re.compile(
    r"\{[^}]*\b" + USER_ID_NAMES + r"\b[^}]*\}\s*=\s*(?:await\s+)?(?:body|data|payload|json|input|\w*\.json\(\))"
    r"|\b(?:body|data|payload|json|input|query|params)\??\.\s*" + USER_ID_NAMES + r"\b"
    r"|searchParams\.get\(\s*['\"]" + USER_ID_NAMES + r"['\"]"
)
SESSION_ID = r"(?:session|auth\w*|currentUser|user|token|payload|decoded|claims)\??\.(?:user\??\.)?(?:id|user_id|userId|sub)\b"
COMPARES_TO_SESSION = re.compile(
    SESSION_ID + r"[^;\n]*(?:===|!==|==|!=)|(?:===|!==|==|!=)[^;\n]*" + SESSION_ID
    + r"|=\s*(?:await\s+)?" + SESSION_ID
)
# Ownership checks delegated to a helper, e.g. isProfilePhotoUploadAuthorized({ targetUserId, authenticatedUserId }).
OWNERSHIP_HELPER = re.compile(r"\b(?:is|can|assert|check|ensure|verify|require)\w*"
                              r"(?:Authori[sz]ed|Authori[sz]e|Owner|Owns|Ownership|Access|Permission)\w*\s*\(")
WRITES = re.compile(r"\b(?:UPDATE|INSERT\s+INTO|DELETE\s+FROM)\b|\.(?:update|insert|delete|upsert|destroy)\s*\(")
PUBLIC_LIST = re.compile(r"\b\w*[Pp]ublic\w*\s*(?::[^=\n]*)?=\s*\[([^\]]*)\]")
QUOTED = re.compile(r"['\"`]([^'\"`\s]+)['\"`]")


def middleware_model(tree) -> dict | None:
    """What Next.js middleware enforces before any handler runs: public paths, a login gate, and role rules.

    Follows middleware.ts and the modules it imports (two levels). Recognizes a public-routes array, a 401 for
    requests without a valid token, and [/^\\/api\\/.../, roles] rules. Returns None when there is no middleware.
    """
    entry = next((path for path in MIDDLEWARE_FILES if path in tree.files), None)
    if entry is None:
        return None
    files, frontier = [entry], [entry]
    for _ in range(2):
        found = []
        for path in frontier:
            for spec, _name in imports(tree.read(path)).values():
                target = tree.resolve(path, spec)
                if target and target not in files:
                    files.append(target)
                    found.append(target)
        frontier = found
    text = "\n".join(tree.read(path) for path in files)
    public = [item for block in PUBLIC_LIST.findall(text) for item in QUOTED.findall(block) if item.startswith("/")]
    rules = []
    for source in ROLE_RULE.findall(text):
        try:
            rules.append(re.compile(source.replace("\\/", "/")))
        except re.error:
            continue
    return {"files": files, "public": public, "rules": rules,
            "login_gate": bool(public) and re.search(r"\b401\b", text) is not None}


def middleware_protection(model: dict | None, path: str) -> tuple[bool, bool, bool]:
    """(public, authenticated, role-checked) for a route path according to the middleware model."""
    if model is None:
        return False, False, False
    sample = re.sub(r"\{[^}]+\}", "x", path)
    public = any(sample == prefix or sample.startswith(prefix.rstrip("/") + "/") for prefix in model["public"])
    role = any(rule.search(sample) for rule in model["rules"])
    return public, (model["login_gate"] and not public) or role, role


def matches_any(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("*") and path.startswith(pattern[:-1]):
            return True
        if path == pattern:
            return True
    return False


def finding(route: dict, method: str, title: str, severity: str, impact: str, remediation: str) -> dict:
    return {
        "title": title, "severity": severity, "verification": "suspected", "method": method,
        "category": "unauthorized_access", "path": route["path"][:256], "owasp": "A01",
        "impact": f"{method} handler in {route['file']}. {impact}"[:2000], "remediation": remediation,
    }


def review(repo: Path, config: dict, revision: str = "HEAD") -> dict:
    repo = repo.resolve()
    sha = checked_revision(repo, revision)
    settings = config.get("review", {})
    tree = Tree(repo, sha)
    analyzer = Analyzer(
        tree,
        DEFAULT_AUTHN + "".join("|" + p for p in settings.get("auth_patterns", [])),
        DEFAULT_AUTHZ + "".join("|" + p for p in settings.get("role_patterns", [])),
    )
    public = settings.get("public_routes", [])
    privileged = settings.get("privileged_prefixes", [])
    excluded = settings.get("exclude_files", [])
    files = sorted(
        f for f in tree.files
        if (ROUTE_FILE.match(f) or PAGES_API.match(f))
        and not any(f.startswith(prefix) for prefix in excluded)
    )
    routes, findings = [], []
    model = middleware_model(tree)
    for file in files:
        source = tree.read(file)
        route = {"path": route_path(file), "file": file, "handlers": []}
        mw_public, mw_authn, mw_authz = middleware_protection(model, route["path"])
        for method, body in handlers(source).items():
            authn, authz = analyzer.body_signals(file, body, 0, {(file, method)})
            is_public = matches_any(route["path"], public) or mw_public
            stub = is_stub(body)
            handler = {"method": method, "authentication": authn or mw_authn, "authorization": authz or mw_authz,
                       "public": is_public, "stub": stub}
            if (mw_authn and not authn) or (mw_authz and not authz):
                handler["middleware"] = True
            route["handlers"].append(handler)
            authn, authz = handler["authentication"], handler["authorization"]
            if is_public or stub:
                continue
            # Admin endpoints exist to act on other users' records; their role gate is the control that matters.
            admin_endpoint = "/admin/" in route["path"] + "/" or matches_any(route["path"], privileged)
            if (authn and not admin_endpoint and ID_FROM_REQUEST.search(body) and WRITES.search(body)
                    and not COMPARES_TO_SESSION.search(body) and not OWNERSHIP_HELPER.search(body)):
                findings.append(finding(
                    route, method, "Handler changes a record chosen by a user ID from the request",
                    "high",
                    "The handler writes using a user ID taken from the request body or query and never compares it "
                    "with the signed-in user, so any user who can reach it may change someone else's record.",
                    "Take the user ID from the session, or check that the requested ID belongs to the signed-in "
                    "user (or that their role allows it) before writing.",
                ))
            if not authn:
                findings.append(finding(
                    route, method, "API handler has no authentication check in code",
                    "high" if method in MUTATING or matches_any(route["path"], privileged) else "medium",
                    "No session or token verification is reachable from this handler. Middleware may still block "
                    "anonymous users, but any signed-in role could reach it. Confirm with the role access test.",
                    "Verify the session inside the handler and deny by default; do not rely on middleware alone.",
                ))
            elif not authz and matches_any(route["path"], privileged):
                findings.append(finding(
                    route, method, "Privileged API handler has no visible role check",
                    "medium",
                    "The user is authenticated, but no role, ownership or 403 check is reachable. "
                    "Lower-privileged users may be able to call it.",
                    "Check the caller's role or ownership on the server and return 403 otherwise.",
                ))
        routes.append(route)
    for route in review_aspnet(tree.read, {f for f in tree.files if not any(f.startswith(p) for p in excluded)},
                               auth_attributes=settings.get("auth_attributes")):
        handler = route["handlers"][0]
        handler["public"] = handler["public"] or matches_any(route["path"], public)
        routes.append(route)
        if handler["public"]:
            continue
        if not handler["authentication"]:
            findings.append(finding(
                route, handler["method"], "API handler has no authentication check in code",
                "high" if handler["method"] in MUTATING or matches_any(route["path"], privileged) else "medium",
                "No [Authorize] on the action, its controller or a base controller, and no global authorization "
                "policy was found, so anonymous visitors may be able to call it.",
                "Add [Authorize] (or a global AuthorizeFilter / FallbackPolicy) and mark only truly public "
                "actions [AllowAnonymous].",
            ))
        elif not handler["authorization"] and matches_any(route["path"], privileged):
            findings.append(finding(
                route, handler["method"], "Privileged API handler has no visible role check",
                "medium",
                "Any signed-in user passes [Authorize]; no role or policy restricts this privileged action.",
                "Use [Authorize(Roles = \"...\")] or a policy that limits it to the right role.",
            ))
    total = sum(len(route["handlers"]) for route in routes)
    return {
        "schema_version": 1, "project": config["project"], "kind": "route-review",
        "revision": sha, "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "route_files": len(routes), "handlers": total,
            "no_authentication": sum(1 for f in findings if f["title"].startswith("API handler has no")),
            "missing_role_check": sum(1 for f in findings if f["title"].startswith("Privileged")),
            "ownership": sum(1 for f in findings if f["title"].startswith("Handler changes a record")),
            "middleware_protected": sum(1 for route in routes for handler in route["handlers"] if handler.get("middleware")),
        },
        "middleware": {"files": model["files"], "login_gate": model["login_gate"],
                       "role_rules": len(model["rules"]), "public_paths": model["public"]} if model else None,
        "routes": routes, "findings": findings,
        "note": "Static source review of one committed revision. Findings are suspected until confirmed by an approved live test.",
    }
