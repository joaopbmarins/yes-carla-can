#!/usr/bin/env python3
"""External Gateway Module (simulated BLE GATT TCP server <-> vcan0).

Replicates vulnerabilities V1 (unauthenticated pairing) and V2 (unintentional
17-second pairing window triggered by HIGH_BEAM) from the E-Spoofer paper.
"""

import argparse
import json
import selectors
import signal
import socket
import sys
import time
from typing import Dict, Optional, Set

import can

from can_network import CAN_Network, VCAN_CHANNEL

PAIRING_WINDOW_SECONDS = 17.0
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5555
DEFAULT_ADV_INTERVAL = 0.2

# Supported external commands mapped uniformly to DBC message names.
ALLOWED_COMMANDS = {
    "HAND_BRAKE": "HAND_BRAKE",
    "DOORS":      "DOORS",
    "THROTTLE":   "THROTTLE",
    "BRAKE":      "BRAKE",
    "STEER":      "STEER",
    "REVERSE":    "REVERSE",
    "GEAR":       "GEAR",
}


class GatewayServer:
    """Bridges an external TCP/BLE-GATT JSON interface to the internal CAN bus."""

    def __init__(
        self,
        can_net: CAN_Network,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        pairing_window: float = PAIRING_WINDOW_SECONDS,
        security_level: int = 1,
        clock=time.monotonic,
    ):
        self.can_net = can_net
        self.host = host
        self.port = port
        self.pairing_window = pairing_window
        self.security_level = security_level
        self._clock = clock

        self._pairing_deadline: Optional[float] = None
        self._was_pairing_active = False
        self._paired_clients: Set[int] = set()
        self._adv_interval = can_net.cycle_times.get(
            "GATEWAY_ADVERTISEMENT", DEFAULT_ADV_INTERVAL
        )
        self._last_adv_sent = 0.0

        self._selector = selectors.DefaultSelector()
        self._server_sock: Optional[socket.socket] = None
        self._recv_buffers: Dict[socket.socket, bytes] = {}
        self._running = False

    @property
    def pairing_mode_active(self) -> bool:
        """Return True while within the 17-second pairing window."""
        if self._pairing_deadline is None:
            return False
        return self._clock() < self._pairing_deadline

    @property
    def remaining_seconds(self) -> float:
        """Seconds remaining in the active pairing window (0.0 if inactive)."""
        if self._pairing_deadline is None:
            return 0.0
        return max(0.0, self._pairing_deadline - self._clock())

    @property
    def paired_clients(self) -> Set[int]:
        return set(self._paired_clients)

    def start_socket(self) -> int:
        """Bind and listen on the TCP socket, returning the bound port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen()
        sock.setblocking(False)
        self._server_sock = sock
        self.port = sock.getsockname()[1]
        self._selector.register(sock, selectors.EVENT_READ, data="accept")
        return self.port

    def close(self):
        """Close all client sockets, server socket, and selector."""
        self._running = False
        for key in list(self._selector.get_map().values()):
            try:
                self._selector.unregister(key.fileobj)
            except Exception:
                pass
            try:
                key.fileobj.close()
            except Exception:
                pass
        self._recv_buffers.clear()
        self._selector.close()
        self._server_sock = None

    def _activate_pairing_window(self):
        """Open or refresh the 17-second pairing window (V2)."""
        was_active = self.pairing_mode_active
        self._pairing_deadline = self._clock() + self.pairing_window
        if not was_active:
            print(
                f"[GATEWAY] HIGH_BEAM detected -> Pairing mode ACTIVE for "
                f"{self.pairing_window:.0f}s (V2)"
            )
        self._was_pairing_active = True

    def poll_can(self):
        """Read pending CAN frames and trigger pairing mode on HIGH_BEAM == 1."""
        while True:
            try:
                msg = self.can_net.bus.recv(timeout=0)
            except can.CanOperationError:
                break
            if msg is None:
                break
            try:
                dbc_msg = self.can_net.db.get_message_by_frame_id(msg.arbitration_id)
            except KeyError:
                continue
            if dbc_msg.name == "GENERAL_LIGHTS":
                decoded = self.can_net.db.decode_message(msg.arbitration_id, msg.data)
                if decoded.get("LIGHTS_HighBeam_signal", 0) == 1:
                    self._activate_pairing_window()

    def _check_window_expiration(self):
        """Log once when the pairing window transitions from active to inactive."""
        active = self.pairing_mode_active
        if self._was_pairing_active and not active:
            print("[GATEWAY] Pairing window EXPIRED -> Pairing mode INACTIVE")
            self._pairing_deadline = None
        self._was_pairing_active = active

    def maybe_send_advertisement(self):
        """Broadcast GATEWAY_ADVERTISEMENT on vcan0 according to its cycle time."""
        now = self._clock()
        if now - self._last_adv_sent >= self._adv_interval:
            try:
                self.can_net.send_gateway_advertisement_msg(
                    pairing_mode_active=self.pairing_mode_active,
                    security_level=self.security_level,
                )
            except Exception:
                pass
            self._last_adv_sent = now

    def handle_request(self, request: dict) -> dict:
        """Process a single JSON request from an external client."""
        req_type = str(request.get("type", "")).lower()

        if req_type == "status":
            return {
                "ok": True,
                "pairing_mode_active": self.pairing_mode_active,
                "remaining_seconds": round(self.remaining_seconds, 3),
                "security_level": self.security_level,
                "paired_clients": sorted(self._paired_clients),
            }

        if req_type == "pair":
            if not self.pairing_mode_active:
                return {"ok": False, "error": "pairing_mode_inactive"}
            try:
                client_id = int(request.get("client_id", 1)) & 0xFF
            except (TypeError, ValueError):
                return {"ok": False, "error": "invalid_client_id"}

            # V1: Accept pairing without credential/PIN verification.
            self._paired_clients.add(client_id)
            try:
                self.can_net.send_gateway_pairing_cmd_msg(client_id, pairing_request=1)
            except Exception:
                pass
            print(f"[GATEWAY] Client {client_id} PAIRED without authentication (V1)")
            return {"ok": True, "paired": True, "client_id": client_id}

        if req_type == "cmd" or ("cmd" in request and not req_type):
            try:
                client_id = int(request.get("client_id", -1))
            except (TypeError, ValueError):
                return {"ok": False, "error": "invalid_client_id"}

            if client_id not in self._paired_clients:
                return {"ok": False, "error": "not_paired"}

            cmd_name = str(request.get("cmd", "")).upper()
            dbc_msg_name = ALLOWED_COMMANDS.get(cmd_name)
            if dbc_msg_name is None:
                return {"ok": False, "error": f"unsupported_command:{cmd_name}"}

            try:
                raw_val = int(request.get("value", 0))
            except (TypeError, ValueError):
                return {"ok": False, "error": "invalid_value"}
            clamped_val = max(0, min(255, raw_val))

            frame = self.can_net._build_msg(dbc_msg_name, clamped_val)
            self.can_net.bus.send(frame)
            return {
                "ok": True,
                "cmd": cmd_name,
                "value": clamped_val,
                "arbitration_id": hex(frame.arbitration_id),
            }

        return {"ok": False, "error": f"unknown_request_type:{req_type}"}

    def _accept_client(self, server_sock: socket.socket):
        conn, _addr = server_sock.accept()
        conn.setblocking(False)
        self._recv_buffers[conn] = b""
        self._selector.register(conn, selectors.EVENT_READ, data="client")

    def _disconnect_client(self, conn: socket.socket):
        try:
            self._selector.unregister(conn)
        except Exception:
            pass
        self._recv_buffers.pop(conn, None)
        try:
            conn.close()
        except Exception:
            pass

    def _read_client(self, conn: socket.socket):
        try:
            chunk = conn.recv(4096)
        except OSError:
            self._disconnect_client(conn)
            return
        if not chunk:
            self._disconnect_client(conn)
            return

        buf = self._recv_buffers.get(conn, b"") + chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                req = json.loads(text)
                resp = self.handle_request(req) if isinstance(req, dict) else {
                    "ok": False, "error": "invalid_json_object"
                }
            except json.JSONDecodeError:
                resp = {"ok": False, "error": "invalid_json"}
            try:
                conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            except OSError:
                self._disconnect_client(conn)
                return
        self._recv_buffers[conn] = buf

    def step(self, timeout: float = 0.01):
        """Run one non-blocking iteration of CAN polling, advertisements, and TCP I/O."""
        self.poll_can()
        self._check_window_expiration()
        self.maybe_send_advertisement()

        if self._server_sock is None:
            return
        for key, _mask in self._selector.select(timeout=timeout):
            if key.data == "accept":
                self._accept_client(key.fileobj)
            else:
                self._read_client(key.fileobj)

    def serve_forever(self):
        """Start the TCP server and run the gateway loop until stopped."""
        bound_port = self.start_socket()
        self._running = True
        print(
            f"[GATEWAY] Listening on {self.host}:{bound_port} "
            f"(pairing window={self.pairing_window:.0f}s)"
        )
        try:
            while self._running:
                self.step(timeout=0.01)
        finally:
            self.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description="External Gateway Module (BLE/TCP -> vcan0) for Yes, CARLA CAN."
    )
    parser.add_argument("--dbc", default="data/carla.dbc", help="Path to the DBC file")
    parser.add_argument("--vcan", default=VCAN_CHANNEL, help=f"CAN interface (default: {VCAN_CHANNEL})")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"TCP bind host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP bind port (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--pairing-window",
        type=float,
        default=PAIRING_WINDOW_SECONDS,
        help=f"Pairing window duration in seconds (default: {PAIRING_WINDOW_SECONDS})",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    can_net = CAN_Network(dbc_path=args.dbc, channel=args.vcan)
    server = GatewayServer(
        can_net=can_net,
        host=args.host,
        port=args.port,
        pairing_window=args.pairing_window,
    )

    def _handle_sig(_signum, _frame):
        server._running = False

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        print("[GATEWAY] Stopped.")


if __name__ == "__main__":
    main()
