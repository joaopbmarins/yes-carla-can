"""CSV compiler for C1 — Communication Surveillance.

Self-contained module: receives a list of FrameRecord objects and produces
two compiled CSVs with per-frame and per-ID statistics.
"""

import csv
import statistics
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

PAYLOAD_BYTES = 8
_PERIODIC_MAD_RATIO = 0.20


@dataclass
class FrameRecord:
    """Minimal CAN frame record."""

    timestamp: float
    arbitration_id: int
    data: bytes
    channel: str = ""


@dataclass
class IDStats:
    """Aggregate statistics for a single CAN arbitration ID."""

    can_id: int
    dlc: int
    frame_count: int
    first_seen: float
    last_seen: float
    rate_hz: float
    dt_mean_ms: float
    dt_std_ms: float
    dt_median_ms: float
    dt_mad_ms: float
    classification: str  # "periodic", "sporadic", or "rare"


def _compute_id_stats(frames: List[FrameRecord]) -> Dict[int, IDStats]:
    """Compute per-ID aggregate statistics from raw frames."""
    # Group frames by arbitration ID
    by_id: Dict[int, List[FrameRecord]] = {}
    for f in frames:
        by_id.setdefault(f.arbitration_id, []).append(f)

    result: Dict[int, IDStats] = {}
    for aid, id_frames in sorted(by_id.items()):
        count = len(id_frames)
        dlc_counter = Counter(len(f.data) for f in id_frames)
        dlc = dlc_counter.most_common(1)[0][0]
        first_ts = id_frames[0].timestamp
        last_ts = id_frames[-1].timestamp
        span = last_ts - first_ts if count > 1 else 0.0
        rate = count / span if span > 0 else float(count)

        # Compute inter-frame deltas
        dts = [
            id_frames[i].timestamp - id_frames[i - 1].timestamp
            for i in range(1, count)
        ]

        if dts:
            dt_mean = statistics.mean(dts)
            dt_std = statistics.pstdev(dts)
            dt_median = statistics.median(dts)
            dt_mad = statistics.median(abs(d - dt_median) for d in dts)
        else:
            dt_mean = dt_std = dt_median = dt_mad = 0.0

        # Classify
        if count < 10:
            classification = "rare"
        elif dt_median <= 0 or dt_mean <= 0:
            classification = "sporadic"
        elif (dt_mad / dt_median) < _PERIODIC_MAD_RATIO and (dt_std / dt_mean) < 0.25:
            classification = "periodic"
        else:
            classification = "sporadic"

        result[aid] = IDStats(
            can_id=aid,
            dlc=dlc,
            frame_count=count,
            first_seen=first_ts,
            last_seen=last_ts,
            rate_hz=round(rate, 3),
            dt_mean_ms=round(dt_mean * 1000, 3),
            dt_std_ms=round(dt_std * 1000, 3),
            dt_median_ms=round(dt_median * 1000, 3),
            dt_mad_ms=round(dt_mad * 1000, 3),
            classification=classification,
        )
    return result


def compile_surveillance_csvs(
    output_dir: Path,
    frames: List[FrameRecord],
) -> Dict[str, str]:
    """Compile both CSVs and return their paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    id_stats = _compute_id_stats(frames)

    frames_path = output_dir / "compiled_frames.csv"
    ids_path = output_dir / "compiled_ids.csv"

    _write_frames_csv(frames_path, frames, id_stats)
    _write_ids_csv(ids_path, id_stats)

    return {
        "compiled_frames_csv": str(frames_path),
        "compiled_ids_csv": str(ids_path),
    }


def _write_frames_csv(
    path: Path,
    frames: List[FrameRecord],
    id_stats: Dict[int, IDStats],
) -> None:
    """Write one row per captured CAN frame."""
    if not frames:
        return

    fieldnames = [
        "timestamp",
        "timestamp_relative",
        "bus",
        "can_id_hex",
        "can_id_dec",
        "dlc",
        "payload_hex",
    ]
    fieldnames += [f"payload_byte_{i}" for i in range(PAYLOAD_BYTES)]
    fieldnames += ["dt_from_prev_same_id", "msg_index_in_id", "classification"]

    t0 = frames[0].timestamp
    last_ts_per_id: Dict[int, float] = {}
    idx_per_id: Dict[int, int] = {}

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        for frame in frames:
            aid = frame.arbitration_id
            stats = id_stats.get(aid)

            dt = ""
            if aid in last_ts_per_id:
                dt = round(frame.timestamp - last_ts_per_id[aid], 6)
            last_ts_per_id[aid] = frame.timestamp

            idx_per_id[aid] = idx_per_id.get(aid, 0) + 1

            row = {
                "timestamp": f"{frame.timestamp:.6f}",
                "timestamp_relative": f"{frame.timestamp - t0:.6f}",
                "bus": frame.channel,
                "can_id_hex": f"0x{aid:03X}",
                "can_id_dec": aid,
                "dlc": len(frame.data),
                "payload_hex": frame.data.hex().upper(),
                "dt_from_prev_same_id": dt,
                "msg_index_in_id": idx_per_id[aid],
                "classification": stats.classification if stats else "",
            }

            for i in range(PAYLOAD_BYTES):
                row[f"payload_byte_{i}"] = (
                    f"{frame.data[i]:02X}" if i < len(frame.data) else ""
                )

            writer.writerow(row)


def _write_ids_csv(path: Path, id_stats: Dict[int, IDStats]) -> None:
    """Write one row per observed CAN ID."""
    if not id_stats:
        return

    fieldnames = [
        "can_id_hex",
        "can_id_dec",
        "dlc",
        "frame_count",
        "first_seen",
        "last_seen",
        "rate_hz",
        "dt_mean_ms",
        "dt_std_ms",
        "dt_median_ms",
        "dt_mad_ms",
        "classification",
    ]

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        for stats in id_stats.values():
            writer.writerow(
                {
                    "can_id_hex": f"0x{stats.can_id:03X}",
                    "can_id_dec": stats.can_id,
                    "dlc": stats.dlc,
                    "frame_count": stats.frame_count,
                    "first_seen": f"{stats.first_seen:.6f}",
                    "last_seen": f"{stats.last_seen:.6f}",
                    "rate_hz": stats.rate_hz,
                    "dt_mean_ms": stats.dt_mean_ms,
                    "dt_std_ms": stats.dt_std_ms,
                    "dt_median_ms": stats.dt_median_ms,
                    "dt_mad_ms": stats.dt_mad_ms,
                    "classification": stats.classification,
                }
            )
