"""HTTP API tests: frozen audits, atomicity, validation errors."""

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from app import server
from app.tarbuild import d, f, layer_b64, ln, wh


def request(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), server.make_handler(server.AuditStore()))
        cls.httpd.daemon_threads = True
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def url(self, path):
        return self.base + path

    def test_healthz(self):
        status, body = request("GET", self.url("/healthz"))
        self.assertEqual((status, body["status"]), (200, "ok"))

    def test_post_then_get_frozen_result(self):
        layers = [
            layer_b64([d("app"), f("app/a.txt", "1"), f("app/b.txt", "2")]),
            layer_b64([wh("app", "a.txt"), f("app/c.txt", "3")]),
        ]
        status, created = request("POST", self.url("/audits"),
                                  {"id": "t-post", "layers": layers})
        self.assertEqual(status, 201)
        self.assertEqual(created["layerCount"], 2)
        self.assertEqual(
            [p["path"] for p in created["paths"]],
            ["app", "app/b.txt", "app/c.txt"])
        self.assertEqual(created["deletions"], [{
            "path": "app/a.txt", "layer": 0, "kind": "whiteout",
            "byLayer": 1, "via": "app/.wh.a.txt",
        }])
        status, got = request("GET", self.url("/audits/t-post"))
        self.assertEqual(status, 200)
        self.assertEqual(got, created)

    def test_frozen_id_conflict(self):
        payload = {"id": "t-frozen", "layers": [layer_b64([f("a", "x")])]}
        status, _ = request("POST", self.url("/audits"), payload)
        self.assertEqual(status, 201)
        status, body = request("POST", self.url("/audits"), payload)
        self.assertEqual(status, 409)
        self.assertIn("frozen", body["error"])
        # Original result untouched.
        _, got = request("GET", self.url("/audits/t-frozen"))
        self.assertEqual([p["path"] for p in got["paths"]], ["a"])

    def test_get_unknown_id(self):
        status, _ = request("GET", self.url("/audits/nope"))
        self.assertEqual(status, 404)

    def test_list_audits(self):
        request("POST", self.url("/audits"),
                {"id": "t-list", "layers": [layer_b64([f("a")])]})
        status, body = request("GET", self.url("/audits"))
        self.assertEqual(status, 200)
        self.assertIn("t-list", body["audits"])

    def test_too_many_layers(self):
        status, body = request(
            "POST", self.url("/audits"),
            {"id": "t-many", "layers": [layer_b64([])] * 7})
        self.assertEqual(status, 400)
        self.assertIn("1..6", body["error"])

    def test_zero_layers(self):
        status, _ = request("POST", self.url("/audits"), {"id": "t-zero", "layers": []})
        self.assertEqual(status, 400)

    def test_invalid_base64(self):
        status, body = request("POST", self.url("/audits"),
                               {"id": "t-b64", "layers": ["!!!not-base64!!!"]})
        self.assertEqual(status, 400)
        self.assertIn("base64", body["error"])

    def test_invalid_gzip(self):
        import base64
        blob = base64.b64encode(b"not a gzip stream at all").decode()
        status, body = request("POST", self.url("/audits"),
                               {"id": "t-gz", "layers": [blob]})
        self.assertEqual(status, 400)
        self.assertIn("layer 0", body["error"])

    def test_invalid_id(self):
        status, _ = request("POST", self.url("/audits"),
                            {"id": "bad/id", "layers": [layer_b64([])]})
        self.assertEqual(status, 400)

    def test_failed_audit_is_atomic(self):
        # Layer 1 (index 1) contains a dangling hard link: the whole audit
        # must be rejected and no partial state may be retrievable.
        layers = [
            layer_b64([d("ok"), f("ok/a.txt", "1")]),
            layer_b64([ln("ok/b.txt", "ok/missing.txt")]),
        ]
        status, body = request("POST", self.url("/audits"),
                               {"id": "t-atomic", "layers": layers})
        self.assertEqual(status, 400)
        self.assertIn("layer 1", body["error"])
        status, _ = request("GET", self.url("/audits/t-atomic"))
        self.assertEqual(status, 404)

    def test_malformed_json(self):
        req = urllib.request.Request(self.url("/audits"), data=b"{not json",
                                     method="POST",
                                     headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
