import json
import tempfile
import unittest
from pathlib import Path

from vaptkit.process import git
from vaptkit.routes import Tree
from vaptkit.usage import reachable_files, unused_dependencies


class UsageTests(unittest.TestCase):
    def repo(self, files: dict[str, str]) -> tuple[Path, str]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name)
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "T")
        for path, text in files.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(text)
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "fixture")
        return repo, git(repo, "rev-parse", "HEAD")

    def test_files_nothing_imports_are_not_reachable(self):
        repo, sha = self.repo({
            "tsconfig.json": '{"compilerOptions": {"paths": {"@/*": ["./*"]}}}',
            "app/page.tsx": "import { db } from '@/lib/db'\nexport default function Page() { return db }",
            "lib/db.ts": "import './pool'\nexport const db = 1",
            "lib/pool.ts": "export const pool = 1",
            "lib/ssl-config.ts": "export const tls = { rejectUnauthorized: false }",
            "lib/env-config.ts": "import { tls } from './ssl-config'\nexport const env = tls",
        })
        reachable = reachable_files(Tree(repo, sha))
        self.assertEqual(reachable >= {"app/page.tsx", "lib/db.ts", "lib/pool.ts"}, True)
        self.assertNotIn("lib/ssl-config.ts", reachable)
        self.assertNotIn("lib/env-config.ts", reachable)

    def test_projects_without_next_entry_points_return_none(self):
        repo, sha = self.repo({"index.js": "console.log(1)"})
        self.assertIsNone(reachable_files(Tree(repo, sha)))

    def test_dependencies_mentioned_only_in_docs_are_unused_but_scripts_count(self):
        repo, sha = self.repo({
            "package.json": json.dumps({"dependencies": {"next": "15", "@google-cloud/aiplatform": "1", "pm2": "5"},
                                        "scripts": {"start": "pm2 start server.js"}}),
            "app/page.tsx": "import Link from 'next/link'",
            "docs/VERTEX_AI.txt": "We use @google-cloud/aiplatform for Vertex.",
            "README.md": "See @google-cloud/aiplatform.",
        })
        self.assertEqual(unused_dependencies(repo, sha), {"@google-cloud/aiplatform"})
