import unittest
import httpx


class TestHttpxTraceStages(unittest.IsolatedAsyncioTestCase):
    async def test_trace_hook_stage_transitions(self):
        connection_state = {"stage": "init"}

        async def trace_hook(event_name, info):
            if event_name == "connection.connect_tcp.started":
                connection_state["stage"] = "tcp_connect"
            elif event_name == "connection.connect_tcp.complete":
                connection_state["stage"] = "tcp_connected"
            elif event_name == "connection.start_tls.started":
                connection_state["stage"] = "tls_handshake"
            elif event_name == "connection.start_tls.complete":
                connection_state["stage"] = "tls_connected"
            elif "send_request" in event_name:
                connection_state["stage"] = "sending_data"
            elif "receive_response" in event_name:
                connection_state["stage"] = "reading_data"

        # Verify initial state
        self.assertEqual(connection_state["stage"], "init")

        # Simulate httpx trace lifecycle events
        await trace_hook("connection.connect_tcp.started", {})
        self.assertEqual(connection_state["stage"], "tcp_connect")

        await trace_hook("connection.connect_tcp.complete", {})
        self.assertEqual(connection_state["stage"], "tcp_connected")

        await trace_hook("connection.start_tls.started", {})
        self.assertEqual(connection_state["stage"], "tls_handshake")

        await trace_hook("connection.start_tls.complete", {})
        self.assertEqual(connection_state["stage"], "tls_connected")

        await trace_hook("httpcore.send_request_headers.started", {})
        self.assertEqual(connection_state["stage"], "sending_data")

        await trace_hook("httpcore.receive_response_headers.complete", {})
        self.assertEqual(connection_state["stage"], "reading_data")
    def test_httpx_request_supports_trace_extension(self):
        # Ensure httpx.Request accepts 'extensions' with 'trace' and 'sni_hostname'
        async def dummy_trace(event_name, info):
            pass

        req = httpx.Request(
            "GET",
            "https://127.0.0.1",
            headers={"Host": "example.com"},
            extensions={"trace": dummy_trace, "sni_hostname": "example.com"}
        )
        self.assertIn("trace", req.extensions)
        self.assertEqual(req.extensions["sni_hostname"], "example.com")


if __name__ == "__main__":
    unittest.main()
