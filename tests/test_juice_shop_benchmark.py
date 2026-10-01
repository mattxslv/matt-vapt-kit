"""Opt-in external-app benchmark. No network, host mounts, ports, or real account data."""
import json
import os
import subprocess
import time
import unittest

from vaptkit.authorization import ObjectEvidence, evaluate_read

IMAGE = "bkimminich/juice-shop@sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d"
SCRIPT = r"""
const assert = require('node:assert/strict');
const base = 'http://127.0.0.1:3000';
let stage = 'startup';
async function call(path, method = 'GET', token, data) {
  const headers = {'Content-Type': 'application/json'};
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(base + path, {
    method, headers, redirect: 'error', signal: AbortSignal.timeout(10000),
    body: data === undefined ? undefined : JSON.stringify(data)
  });
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch { body = null; }
  return {status: response.status, body};
}
async function register(label) {
  stage = `register-${label}`;
  const email = `mvk-${label}@example.invalid`;
  const password = 'synthetic-benchmark-only';
  const created = await call('/api/Users/', 'POST', null, {email, password, passwordRepeat: password});
  assert.equal(created.status, 201, 'Synthetic account creation failed');
  stage = `login-${label}`;
  const login = await call('/rest/user/login', 'POST', null, {email, password});
  assert.equal(login.status, 200, 'Synthetic login failed');
  const auth = login.body.authentication;
  assert.ok(auth.token && auth.bid, 'Missing synthetic session');
  return {token: auth.token, basket: auth.bid, user: created.body.data.id};
}
async function main() {
  const alice = await register('alice');
  const bob = await register('bob');
  stage = 'identity-checks';
  assert.notEqual(alice.user, bob.user);
  assert.notEqual(alice.basket, bob.basket);
  assert.notEqual(alice.token, bob.token);
  stage = 'basket-setup';
  const added = await call('/api/BasketItems/', 'POST', alice.token,
    {BasketId: alice.basket, ProductId: 1, quantity: 3});
  stage = `basket-setup-http-${added.status}`;
  assert.ok(added.status === 200 || added.status === 201, 'Synthetic basket setup failed');
  stage = 'owner-control';
  const expected = await call(`/rest/basket/${alice.basket}`, 'GET', alice.token);
  const reference = expected.body.data;
  assert.equal(reference.UserId, alice.user);
  assert.ok(reference.Products.length > 0, 'Owner basket control is empty');
  function evidence(result) {
    const data = result.body && result.body.data;
    return {
      status: result.status,
      body_assessed: result.body !== null,
      object_matches: !!data && data.id === reference.id && data.UserId === reference.UserId
        && Array.isArray(data.Products) && JSON.stringify(data.Products) === JSON.stringify(reference.Products)
    };
  }
  const own = [], peer = [], anonymous = [];
  stage = 'access-attempts';
  for (let n = 0; n < 2; n++) {
    own.push(evidence(await call(`/rest/basket/${alice.basket}`, 'GET', alice.token)));
    peer.push(evidence(await call(`/rest/basket/${alice.basket}`, 'GET', bob.token)));
    anonymous.push(evidence(await call(`/rest/basket/${alice.basket}`)));
  }
  process.stdout.write(JSON.stringify({control: evidence(expected), own, peer, anonymous}));
}
main().catch(() => { console.error(`Synthetic fixture failed at ${stage}; values withheld.`); process.exit(1); });
"""


@unittest.skipUnless(os.environ.get("MVK_RUN_JUICE_SHOP") == "1", "opt-in isolated external-app benchmark")
class JuiceShopBenchmark(unittest.TestCase):
    def test_independent_basket_ownership(self):
        # --pull=never ensures this test cannot silently download an unreviewed image.
        subprocess.run(["docker", "image", "inspect", IMAGE], check=True, capture_output=True, timeout=15)
        started = subprocess.run([
            "docker", "run", "--detach", "--rm", "--pull=never", "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "1g", "--cpus", "1", "--pids-limit", "128", IMAGE,
        ], capture_output=True, text=True, check=True, timeout=30)
        container = started.stdout.strip()
        self.assertRegex(container, r"^[a-f0-9]{64}$")
        try:
            ready = False
            for _ in range(45):
                result = subprocess.run([
                    "docker", "exec", container, "/nodejs/bin/node", "-e",
                    "fetch('http://127.0.0.1:3000/rest/products/search',"
                    "{signal:AbortSignal.timeout(1000)}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))",
                ], capture_output=True, timeout=5)
                if result.returncode == 0:
                    ready = True
                    break
                time.sleep(1)
            self.assertTrue(ready, "Isolated benchmark app did not become ready")
            result = subprocess.run(["docker", "exec", "-i", container, "/nodejs/bin/node"],
                                    input=SCRIPT, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                diagnostic = result.stderr.strip()
                if not diagnostic.startswith("Synthetic fixture failed at ") or len(diagnostic) > 120:
                    diagnostic = "Independent fixture request failed; raw output withheld"
                self.fail(diagnostic)
            facts = json.loads(result.stdout)
            control = ObjectEvidence(**facts["control"])
            actual = {
                label: evaluate_read(control, [ObjectEvidence(**item) for item in facts[label]], allowed=allowed)
                for label, allowed in (("own", True), ("peer", False), ("anonymous", False))
            }
            self.assertEqual(actual["own"], "allowed")
            self.assertEqual(actual["peer"], "violation")
            self.assertTrue(all(item["status"] == 401 and not item["object_matches"] for item in facts["anonymous"]))
            # The independent app's non-JSON denial is deliberately not treated as assessed object evidence.
            self.assertEqual(actual["anonymous"], "inconclusive")
            print("\nIndependent Juice Shop ownership benchmark: " + json.dumps(actual, sort_keys=True))
        finally:
            subprocess.run(["docker", "stop", "--time", "5", container],
                           check=True, capture_output=True, timeout=20)
