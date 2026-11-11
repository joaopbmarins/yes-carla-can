"""C1 — Communication Surveillance (passive sniffing).

Passive node listens to CAN traffic (live or replay) and compiles
captured frame data into enriched CSVs.
"""

import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from attacks.surveillance_csv_compiler import FrameRecord

DEFAULT_CHANNEL = "vcan1"
DEFAULT_INTERFACE = "socketcan"
DEFAULT_OUTPUT_ROOT = Path("traffic_logs") / "surveillance"

_CANDUMP_RE = re.compile(
    r"^\((?P<ts>\d+\.\d+)\)\s+(?P<bus>\S+)\s+(?P<id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)"
)


def parse_candump_log(path: Path) -> List[FrameRecord]:
    """Parse frames from a candump -l log."""
    frames = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _CANDUMP_RE.match(line.strip())
            if m:
                frames.append(
                    FrameRecord(
                        float(m.group("ts")),
                        int(m.group("id"), 16),
                        bytes.fromhex(m.group("data")),
                        m.group("bus"),
                    )
                )
    return frames


class SurveillanceSession:
    """Passive surveillance run: capture (live or replay) then compile CSVs."""

    def __init__(
        self,
        channel: str = DEFAULT_CHANNEL,
        interface: str = DEFAULT_INTERFACE,
        output_dir: Optional[Path] = None,
        progress=None,
    ) -> None:
        self.channel = channel
        self.interface = interface
        self.output_dir = output_dir
        self.progress = progress or self._default_progress
        self.captured_frames: List[FrameRecord] = []
        self._unique_ids: set = set()
        self._mode = "live"
        self._replay_source = ""

    @staticmethod
    def _default_progress(frames: int, n_ids: int, rate: float) -> None:
        sys.stdout.write(
            f"\r[surveillance] frames={frames}  ids={n_ids}  rate={rate:.1f} msg/s   "
        )
        sys.stdout.flush()

    def run_live(self, duration: float = 60.0) -> None:
        import can

        self._mode = "live"
        bus = can.interface.Bus(channel=self.channel, interface=self.interface)
        deadline = time.monotonic() + max(duration, 0.0)
        last_report = time.monotonic()
        while time.monotonic() < deadline:
            try:
                msg = bus.recv(timeout=0.2)
            except can.CanError:
                continue
            if msg:
                frame = FrameRecord(
                    msg.timestamp or time.time(),
                    msg.arbitration_id,
                    bytes(msg.data),
                    self.channel,
                )
                self.captured_frames.append(frame)
                self._unique_ids.add(msg.arbitration_id)
            now = time.monotonic()
            if now - last_report >= 0.5:
                last_report = now
                self._emit_progress()

    def run_replay(self, path: Path) -> None:
        self._mode = "replay"
        self._replay_source = str(path)
        frames = parse_candump_log(path)
        if not frames:
            raise ValueError(f"No candump frames parsed from {path}")
        self.captured_frames = frames
        self._unique_ids = {f.arbitration_id for f in frames}
        self._emit_progress()

    def _emit_progress(self) -> None:
        n = len(self.captured_frames)
        if n >= 2:
            span = (
                self.captured_frames[-1].timestamp
                - self.captured_frames[0].timestamp
            )
            rate = n / span if span > 0 else 0.0
        else:
            rate = 0.0
        self.progress(n, len(self._unique_ids), rate)

    def generate_csvs(self) -> Dict[str, str]:
        from attacks.surveillance_csv_compiler import compile_surveillance_csvs

        if not self.captured_frames:
            raise RuntimeError("No frames captured; nothing to compile.")
        if self.output_dir is None:
            self.output_dir = (
                DEFAULT_OUTPUT_ROOT
                / f"surveillance-{time.strftime('%Y%m%d-%H%M%S')}"
            )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        paths = compile_surveillance_csvs(self.output_dir, self.captured_frames)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return paths


def communication_surveillance_func(
    channel: str = DEFAULT_CHANNEL,
    duration: float = 60.0,
    replay_path: Optional[str] = None,
    output_dir: Optional[str] = None,
    progress=None,
) -> Dict[str, str]:
    """Entry point used by cyberattacks_module.py."""
    session = SurveillanceSession(
        channel=channel,
        output_dir=Path(output_dir) if output_dir else None,
        progress=progress,
    )
    if replay_path:
        session.run_replay(Path(replay_path))
    else:
        try:
            session.run_live(duration=duration)
        except KeyboardInterrupt:
            pass
    return session.generate_csvs()


if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        description="C1 Communication Surveillance — compile CAN traffic into CSVs."
    )
    parser.add_argument("log", help="candump -l log file to analyse")
    parser.add_argument("--out", default=None, help="output directory")
    args = parser.parse_args()
    result = communication_surveillance_func(
        replay_path=args.log, output_dir=args.out
    )
    for label, key in [
        ("Compiled frames", "compiled_frames_csv"),
        ("Compiled IDs", "compiled_ids_csv"),
    ]:
        sys.stdout.write(f"{label:16}: {result[key]}\n")
