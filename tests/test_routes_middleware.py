import tempfile
import unittest
from pathlib import Path

from vaptkit.process import git
from vaptkit.routes import review

MIDDLEWARE = """
import { gate } from '@/lib/gate'
export async function middleware(req) { return gate(req) }
export const config = { matcher: ['/(api|trpc)(.*)'] }
"""

GATE = r"""
const ADMIN_ROLES = ['administrator']
const API_ROLE_RULES = [
  [/^\/api\/admin(\/|$)/, ADMIN_ROLES],
  [/^\/api\/applications\/[^/]+\/review(\/|$)/, ['evaluator', 'administrator']],
]
export async function gate(req) {
  const publicRoutes = ['/login', '/api/auth', '/api/health']
  const isPublicRoute = publicRoutes.some(route => req.nextUrl.pathname.startsWith(route))
  if (!hasValidToken && !isPublicRoute) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
}
"""

VULNERABLE_PROFILE = """
export async function PUT(request) {
  const body = await request.json()
  const { userId, ...updates } = body
  await query(`UPDATE staff SET department = $1 WHERE user_id = $2`, [updates.department, userId])
  return NextResponse.json({ ok: true })
}
"""

FIXED_PROFILE = """
export async function PUT(request) {
  const authResult = await requireAuth(request)
  const body = await request.json()
  const { userId: requestedUserId, ...updates } = body
  const userId = authResult.user.id
  if (requestedUserId && requestedUserId !== userId) return NextResponse.json({}, { status: 403 })
  await query(`UPDATE staff SET department = $1 WHERE user_id = $2`, [updates.department, userId])
  return NextResponse.json({ ok: true })
}
"""


class MiddlewareAwareReviewTests(unittest.TestCase):
    def build(self, files: dict[str, str]) -> dict:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name)
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "T")
        (repo / "tsconfig.json").write_text('{"compilerOptions": {"paths": {"@/*": ["./*"]}}}')
        for path, text in {"middleware.ts": MIDDLEWARE, "lib/gate.ts": GATE, **files}.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(text)
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "fixture")
        return review(repo, {"project": "fixture", "review": {}})

    def test_login_gate_and_role_rules_protect_handlers_and_public_routes_stay_public(self):
        result = self.build({
            "app/api/reports/route.ts": "export async function GET() { return NextResponse.json(await rows()) }",
            "app/api/applications/[id]/review/route.ts": "export async function POST() { return NextResponse.json({}) }",
            "app/api/health/route.ts": "export async function GET() { return NextResponse.json({ ok: true }) }",
        })
        handlers = {route["path"]: route["handlers"][0] for route in result["routes"]}
        self.assertEqual(result["findings"], [])
        self.assertTrue(handlers["/api/reports"]["authentication"])
        self.assertTrue(handlers["/api/reports"]["middleware"])
        self.assertTrue(handlers["/api/applications/{id}/review"]["authorization"])
        self.assertTrue(handlers["/api/health"]["public"])
        self.assertTrue(result["middleware"]["login_gate"])
        self.assertEqual(result["middleware"]["role_rules"], 2)

    def test_handler_writing_with_a_user_id_from_the_body_is_flagged(self):
        result = self.build({"app/api/evaluator/profile/route.ts": VULNERABLE_PROFILE})
        self.assertEqual([finding["title"] for finding in result["findings"]],
                         ["Handler changes a record chosen by a user ID from the request"])
        self.assertEqual(result["summary"]["ownership"], 1)

    def test_handler_that_compares_with_the_session_user_is_not_flagged(self):
        self.assertEqual(self.build({"app/api/evaluator/profile/route.ts": FIXED_PROFILE})["findings"], [])

    def test_admin_endpoints_may_act_on_other_users(self):
        self.assertEqual(self.build({"app/api/admin/users/update/route.ts": VULNERABLE_PROFILE})["findings"], [])

    def test_without_middleware_unauthenticated_handlers_are_still_flagged(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name)
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "T")
        (repo / "app/api/reports").mkdir(parents=True)
        (repo / "app/api/reports/route.ts").write_text("export async function GET() { return NextResponse.json(await rows()) }")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "fixture")
        result = review(repo, {"project": "fixture", "review": {}})
        self.assertIsNone(result["middleware"])
        self.assertEqual(result["summary"]["no_authentication"], 1)


    def test_ownership_checked_by_a_helper_is_not_flagged(self):
        helper_checked = VULNERABLE_PROFILE.replace(
            "  await query(", "  if (!isProfileEditAuthorized({ targetUserId: userId, session })) return forbidden()\n  await query(")
        self.assertEqual(self.build({"app/api/evaluator/profile/route.ts": helper_checked})["findings"], [])


class SymmetricMethodCoverageTests(unittest.TestCase):
    """The real DTAP bug was a PUT handler; confirm every HTTP method gets the same scrutiny as GET."""

    def test_every_http_method_is_analyzed_and_an_unprotected_write_is_flagged_regardless_of_method(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name)
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "T")
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            (repo / f"app/api/records/{method.lower()}").mkdir(parents=True)
            (repo / f"app/api/records/{method.lower()}/route.ts").write_text(
                f"export async function {method}(req) {{ return NextResponse.json(await act(req)) }}")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "fixture")
        result = review(repo, {"project": "fixture", "review": {}})
        analyzed = {route["handlers"][0]["method"] for route in result["routes"]}
        self.assertEqual(analyzed, {"GET", "POST", "PUT", "PATCH", "DELETE"})
        flagged = {route["handlers"][0]["method"] for route in result["routes"]
                  if not route["handlers"][0]["authentication"]}
        self.assertEqual(flagged, {"GET", "POST", "PUT", "PATCH", "DELETE"})
        self.assertEqual(result["summary"]["no_authentication"], 5)
