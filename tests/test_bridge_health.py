from __future__ import annotations

import json
import unittest
from http import HTTPStatus
from types import SimpleNamespace

from bridge.server import BridgeServer


class FakeResponse:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}


class FakeConnection:
    def __init__(self) -> None:
        self.status = None
        self.text = None
        self.response = FakeResponse()

    def respond(self, status, text):
        self.status = status
        self.text = text
        return self.response


class BridgeHealthRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = BridgeServer(host="127.0.0.1", port=9897)

    def test_bridge_health_http_response_is_json_and_read_only(self) -> None:
        connection = FakeConnection()
        response = self.bridge.process_http_request(
            connection, SimpleNamespace(path="/api/health")
        )
        self.assertIs(response, connection.response)
        self.assertEqual(connection.status, HTTPStatus.OK)
        payload = json.loads(connection.text)
        self.assertEqual(payload["service"], "sovereignty-python-bridge")
        self.assertEqual(payload["port"], 9897)
        self.assertEqual(payload["transport"], "websocket+http-health")
        self.assertTrue(connection.response.headers["Content-Type"].startswith("application/json"))
        self.assertEqual(connection.response.headers["Cache-Control"], "no-store")

    def test_bridge_health_hook_does_not_intercept_other_http_paths(self) -> None:
        self.assertIsNone(
            self.bridge.process_http_request(
                FakeConnection(), SimpleNamespace(path="/api/keys")
            )
        )


if __name__ == "__main__":
    unittest.main()
