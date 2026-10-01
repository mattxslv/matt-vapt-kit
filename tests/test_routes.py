import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vaptkit.report import merge_source_review
from vaptkit.routes import function_body, is_stub, review, route_path, strip_comments

FILES = {
    "tsconfig.json": '{"compilerOptions": {"paths": {"@/*": ["./*"]},}}',
    "lib/auth.ts": """
import { jwtVerify } from 'jose'
type User = { role: string }
export async function getUser(req: Request): Promise<{ user: User } | null> {
  const token = req.headers.get('cookie')
  return token ? { user: (await jwtVerify(token, key)).payload as User } : null
}
export async function requireAdmin(req: Request): Promise<{ ok: boolean }> {
  const result = await getUser(req)
  if (result?.user.role !== 'admin') return { ok: false }
  return { ok: true }
}
export class AuthService {
  static async current() { return new AuthService().check() }
  async check() { return this.lookup() }
  async lookup() { return null }
}
""",
    "lib/index.ts": "export * from './auth'\n",
    "app/api/admin/users/route.ts": """
import { requireAdmin } from '@/lib/auth'
export async function GET(req: Request) { const a = await requireAdmin(req); return Response.json(a) }
""",
    "app/api/admin/stats/route.ts": """
import { getUser } from '../../../../lib'
export async function GET(req: Request) { const u = await getUser(req); return Response.json(u) }
""",
    "app/api/open/route.ts": """
import { db } from '@/lib/db'
export async function GET() {
  // const user = await requireAuth()
  /* verifyToken(token) */
  return Response.json(await db.all())
}
export async function POST(req: Request) { return Response.json(await req.json()) }
""",
    "app/api/class/route.ts": """
import { AuthService } from '@/lib/auth'
export async function GET() { await AuthService.current(); return Response.json({}) }
""",
    "app/api/dynamic/[id]/route.ts": """
export async function GET() {
  const { getUser } = await import('@/lib/auth')
  return Response.json(await getUser())
}
""",
    "app/api/stub/route.ts": """
export async function POST() {
  return Response.json({ error: 'Not implemented' }, { status: 501 })
}
""",
    "app/api/cron/route.ts": """
export async function POST(req: Request) {
  const secret = process.env.CRON_SECRET
  if (req.headers.get('authorization') !== `Bearer ${secret}`) return new Response(null, { status: 401 })
  return Response.json(await cleanup())
}
""",
    "app/api/logs/route.ts": """
import { audit } from '@/lib/log'
export async function GET() { audit('x'); return Response.json(await readLogs()) }
""",
    "lib/log.ts": "export function audit(e) { if (process.env.NODE_ENV === 'production') send(e) }\n",
    "app/api/factory/route.ts": """
import { createAuthClient } from '@/lib/client'
export async function GET(req: Request) {
  const client = createAuthClient()
  const { data } = await client.getUser(req.headers.get('authorization'))
  return Response.json(data)
}
""",
    "lib/client.ts": """
import { Client } from './client-impl'
export function createAuthClient() { return new Client() }
""",
    "lib/client-impl.ts": """
import { jwtVerify } from 'jose'
export class Client { async getUser(token) { return jwtVerify(token, key) } }
""",
    "app/api/auth/signin/route.ts": "export async function POST() { return Response.json({}) }\n",
    "app/(public)/api/wrapped/route.ts": """
import { withAuth } from '@/lib/wrap'
export const GET = withAuth(async (req: Request) => { return Response.json({}) })
""",
    "lib/wrap.ts": """
import { getUser } from './auth'
export function withAuth(handler) { return async (req) => { await getUser(req); return handler(req) } }
""",
}

CONFIG = {
    "project": "fixture",
    "review": {"public_routes": ["/api/auth/*"], "privileged_prefixes": ["/api/admin*"]},
}


class RouteReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.repo = Path(cls.directory.name)
        for name, content in FILES.items():
            path = cls.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        for command in (["init", "-q"], ["add", "-A"],
                        ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "fixture"]):
            subprocess.run(["git", "-C", str(cls.repo), *command], check=True)
        (cls.repo / "app/api/open/route.ts").write_text("// uncommitted edits are ignored\n")
        cls.result = review(cls.repo, CONFIG)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def flagged(self):
        return {(f["path"], f["impact"].split(" ")[0]) for f in self.result["findings"]
                if f["title"] == "API handler has no authentication check in code"}

    def test_only_true_positives_flagged(self):
        self.assertEqual(self.flagged(), {("/api/open", "GET"), ("/api/open", "POST"), ("/api/class", "GET"), ("/api/logs", "GET")})

    def test_severity_and_verification(self):
        by_method = {f["impact"].split(" ")[0]: f for f in self.result["findings"] if f["path"] == "/api/open"}
        self.assertEqual(by_method["POST"]["severity"], "high")
        self.assertEqual(by_method["GET"]["severity"], "medium")
        self.assertTrue(all(f["verification"] == "suspected" for f in self.result["findings"]))

    def test_inventory_records_helpers_public_and_stubs(self):
        routes = {r["path"]: r["handlers"] for r in self.result["routes"]}
        self.assertTrue(routes["/api/admin/users"][0]["authorization"])
        self.assertTrue(routes["/api/admin/stats"][0]["authentication"])
        self.assertTrue(routes["/api/dynamic/{id}"][0]["authentication"])
        self.assertTrue(routes["/api/wrapped"][0]["authentication"])
        self.assertTrue(routes["/api/auth/signin"][0]["public"])
        self.assertTrue(routes["/api/stub"][0]["stub"])
        self.assertTrue(routes["/api/cron"][0]["authentication"])
        self.assertTrue(routes["/api/factory"][0]["authentication"])
        self.assertEqual(self.result["summary"]["handlers"], 12)

    def test_default_privileged_finding(self):
        titles = {(f["path"], f["title"]) for f in self.result["findings"]}
        self.assertIn(("/api/admin/stats", "Privileged API handler has no visible role check"), titles)
        self.assertEqual(len(self.result["findings"]), 5)

    def test_privileged_route_without_role_check(self):
        config = {"project": "fixture", "review": {"privileged_prefixes": ["/api/admin/stats"]}}
        titles = {(f["path"], f["title"]) for f in review(self.repo, config)["findings"]}
        self.assertIn(("/api/admin/stats", "Privileged API handler has no visible role check"), titles)
        self.assertNotIn(("/api/admin/users", "Privileged API handler has no visible role check"), titles)

    def test_helpers(self):
        self.assertEqual(route_path("app/(group)/api/x/[id]/[...rest]/route.ts"), "/api/x/{id}/{rest*}")
        self.assertEqual(route_path("pages/api/users/index.ts"), "/api/users")
        self.assertNotIn("verifyToken", strip_comments("a // verifyToken\n/* verifyToken */ b"))
        self.assertIn("'// keep'", strip_comments("x = '// keep'"))
        body = function_body("async function f(a: A): Promise<{ u: U }> { return check(a) }", "f")
        self.assertIn("check(a)", body)
        self.assertTrue(is_stub("function POST() { return NextResponse.json({}, { status: 501 }) }"))
        self.assertFalse(is_stub("async function POST() { await db.drop(); return x({}, { status: 404 }) }"))
        self.assertTrue(is_stub("function GET() { return NextResponse.json({ status: 'ready' }) }"))
        self.assertFalse(is_stub("function GET() { return NextResponse.json({ key: process.env.KEY }) }"))
        self.assertFalse(is_stub("async function POST(req) { return NextResponse.json(req.body) }"))

    def test_merge_into_report(self):
        result = json.loads((Path(__file__).parent / "fixtures/assessment.json").read_text())
        merged = merge_source_review(result, dict(self.result, project=result["project"]))
        self.assertEqual(len(merged["findings"]), len(result["findings"]) + 5)
        self.assertIn("Static source review", merged["coverage"]["note"])
        with self.assertRaises(Exception):
            merge_source_review(result, self.result)


if __name__ == "__main__":
    unittest.main()
