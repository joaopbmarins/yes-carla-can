"""Unit tests for gateway_module.py and attacks/malicious_pairing.py."""
import queue
import threading
import time
from unittest.mock import MagicMock, patch

import can
import pytest

from attacks.malicious_pairing import run_malicious_pairing_attack
from can_network.network import CAN_Network
from constants import GATEWAY_DBC
from gateway_module import GatewayServer, PAIRING_WINDOW_SECONDS


class FakeClock:
    """Deterministic monotonic clock for testing the 17-second pairing window."""

    def __init__(self, start: float = 100.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float):
        self.now += seconds


@pytest.fixture
def gateway_env(tmp_path):
    """Return (gateway, can_net, mock_bus, fake_clock) using a mocked CAN bus."""
    dbc_file = tmp_path / "gateway.dbc"
    dbc_file.write_text(GATEWAY_DBC)

    mock_bus = MagicMock()
    mock_bus.recv.return_value = None
    with patch("can.ThreadSafeBus", return_value=mock_bus):
        can_net = CAN_Network(dbc_path=str(dbc_file), channel="vcan0")

    clock = FakeClock()
    gw = GatewayServer(can_net=can_net, clock=clock)
    return gw, can_net, mock_bus, clock


def _make_high_beam_frame(can_net: CAN_Network, active: bool) -> can.Message:
    """Build a GENERAL_LIGHTS CAN frame with HighBeam set to 1 or 0."""
    dbc_msg = can_net.db.get_message_by_name("GENERAL_LIGHTS")
    signals = {s.name: 0 for s in dbc_msg.signals}
    signals["LIGHTS_HighBeam_signal"] = 1 if active else 0
    return can.Message(
        arbitration_id=dbc_msg.frame_id,
        data=dbc_msg.encode(signals),
        is_extended_id=dbc_msg.is_extended_frame,
    )


def test_commands_and_pairing_rejected_before_high_beam(gateway_env):
    """External commands and pairing requests are rejected while pairing mode is inactive."""
    gw, _, mock_bus, _ = gateway_env

    assert not gw.pairing_mode_active

    pair_resp = gw.handle_request({"type": "pair", "client_id": 7})
    assert pair_resp == {"ok": False, "error": "pairing_mode_inactive"}

    cmd_resp = gw.handle_request(
        {"type": "cmd", "client_id": 7, "cmd": "HAND_BRAKE", "value": 1}
    )
    assert cmd_resp == {"ok": False, "error": "not_paired"}
    mock_bus.send.assert_not_called()


def test_high_beam_opens_17s_window_and_expires(gateway_env):
    """HIGH_BEAM == 1 activates pairing mode for 17s, then expires cleanly."""
    gw, can_net, mock_bus, clock = gateway_env

    mock_bus.recv.side_effect = [_make_high_beam_frame(can_net, True), None]
    gw.poll_can()

    assert gw.pairing_mode_active is True
    assert gw.remaining_seconds == pytest.approx(PAIRING_WINDOW_SECONDS)

    clock.advance(16.9)
    assert gw.pairing_mode_active is True

    clock.advance(0.1)
    assert gw.pairing_mode_active is False
    assert gw.remaining_seconds == 0.0

    # Pairing after expiration must be rejected.
    pair_resp = gw.handle_request({"type": "pair", "client_id": 12})
    assert pair_resp == {"ok": False, "error": "pairing_mode_inactive"}


@pytest.mark.parametrize(
    "cmd_name, value, expected_dbc_msg, expected_signal",
    [
        ("HAND_BRAKE", 1, "HAND_BRAKE", "HAND_BRAKE_signal"),
        ("DOORS", 1, "DOORS", "DOORS_signal"),
        ("THROTTLE", 200, "THROTTLE", "THROTTLE_signal"),
    ],
)
def test_paired_client_injects_expected_can_frame(
    gateway_env, cmd_name, value, expected_dbc_msg, expected_signal
):
    """Unauthenticated pairing succeeds during the window and injected cmds emit CAN frames."""
    gw, can_net, mock_bus, _ = gateway_env

    mock_bus.recv.side_effect = [_make_high_beam_frame(can_net, True), None]
    gw.poll_can()

    pair_resp = gw.handle_request({"type": "pair", "client_id": 42})
    assert pair_resp == {"ok": True, "paired": True, "client_id": 42}

    # Verify GATEWAY_PAIRING_CMD was emitted on vcan0.
    pairing_frame = mock_bus.send.call_args_list[-1][0][0]
    decoded_pairing = can_net.db.decode_message(
        pairing_frame.arbitration_id, pairing_frame.data
    )
    assert decoded_pairing["client_id"] == 42
    assert decoded_pairing["pairing_request"] == 1

    # Inject target command and verify official DBC frame on vcan0.
    cmd_resp = gw.handle_request(
        {"type": "cmd", "client_id": 42, "cmd": cmd_name, "value": value}
    )
    assert cmd_resp["ok"] is True

    injected_frame = mock_bus.send.call_args_list[-1][0][0]
    dbc_msg = can_net.db.get_message_by_name(expected_dbc_msg)
    assert injected_frame.arbitration_id == dbc_msg.frame_id
    decoded_cmd = can_net.db.decode_message(
        injected_frame.arbitration_id, injected_frame.data
    )
    assert decoded_cmd[expected_signal] == value


def test_end_to_end_tcp_malicious_pairing_attack(tmp_path):
    """End-to-end TCP test: HIGH_BEAM triggers pairing and malicious_pairing injects HAND_BRAKE."""
    dbc_file = tmp_path / "gateway.dbc"
    dbc_file.write_text(GATEWAY_DBC)

    rx_queue: queue.Queue = queue.Queue()
    mock_bus = MagicMock()
    mock_bus.recv.side_effect = lambda timeout=0: (
        rx_queue.get_nowait() if not rx_queue.empty() else None
    )
    with patch("can.ThreadSafeBus", return_value=mock_bus):
        can_net = CAN_Network(dbc_path=str(dbc_file), channel="vcan0")

    gw = GatewayServer(can_net=can_net, host="127.0.0.1", port=0)
    bound_port = gw.start_socket()
    gw._running = True

    def _run_gw():
        try:
            while gw._running:
                gw.step(timeout=0.01)
        finally:
            gw.close()

    server_thread = threading.Thread(target=_run_gw, daemon=True)
    server_thread.start()

    try:
        # Simulate HIGH_BEAM activation after 50ms so Phase 1 polling observes the transition.
        def _trigger_high_beam():
            time.sleep(0.05)
            rx_queue.put(_make_high_beam_frame(can_net, True))

        threading.Thread(target=_trigger_high_beam, daemon=True).start()

        run_malicious_pairing_attack(
            target="hand_brake",
            host="127.0.0.1",
            port=bound_port,
            period=0.01,
            poll_interval=0.02,
            client_id=99,
            max_injections=2,
        )

        hb_id = can_net.db.get_message_by_name("HAND_BRAKE").frame_id
        sent_frames = [call[0][0] for call in mock_bus.send.call_args_list]
        hb_frames = [f for f in sent_frames if f.arbitration_id == hb_id]
        assert len(hb_frames) >= 2
        assert can_net.db.decode_message(hb_id, hb_frames[-1].data)["HAND_BRAKE_signal"] == 1
    finally:
        gw._running = False
        server_thread.join(timeout=2.0)
