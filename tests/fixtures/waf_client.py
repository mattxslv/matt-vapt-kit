"""In-container loopback client; emits derived evidence, never payloads or raw responses."""
import http.client
import json
import secrets
import sys
from urllib.parse import urlencode


def call(port, method, path, data=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {"Host": "fixture.local", "User-Agent": "MVK-local-WAF-fixture", "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=json.dumps(data) if data is not None else None, headers=headers)
        response = connection.getresponse()
        body = response.read(8193)
        try:
            value = json.loads(body) if len(body) <= 8192 else None
        except ValueError:
            value = None
        return response.status, value
    finally:
        connection.close()


def trial(case, port):
    key = secrets.token_hex(16)
    parameters = {"key": key}
    if case["method"] == "GET":
        parameters["q"] = case["value"]
    endpoint = "/denied" if case["id"] == "application-denial" else "/echo"
    status, value = call(
        port, case["method"], endpoint + "?" + urlencode(parameters),
        {"q": case["value"]} if case["method"] == "POST" else None,
    )
    seen_status, seen = call(8081, "GET", "/seen?" + urlencode({"key": key}))
    if seen_status != 200 or not isinstance(seen, dict) or type(seen.get("seen")) is not bool:
        raise ValueError("Origin evidence unavailable")
    return {"key": key, "status": status,
            "marker_matches": isinstance(value, dict) and value.get("marker") == key,
            "origin_seen": seen["seen"]}


if __name__ == "__main__":
    try:
        cases = json.load(sys.stdin)
        output = []
        for case in cases:
            output.append({"id": case["id"], "control": trial(case, 8081),
                           "attempts": [trial(case, 8080) for _ in range(2)]})
        print(json.dumps(output))
    except (OSError, http.client.HTTPException, ValueError, KeyError):
        print("Local WAF fixture failed; raw details withheld.", file=sys.stderr)
        raise SystemExit(1)
