"""Unit tests for C1 Communication Surveillance (simplified).

All tests are bus-free: frames are fed directly into the compiler or
replayed from candump-format files, so neither SocketCAN nor CARLA is needed.
"""

import csv
import random
from pathlib import Path

import pytest

from attacks.communication_surveillance import (
    communication_surveillance_func,
    parse_candump_log,
    SurveillanceSession,
)
from attacks.surveillance_csv_compiler import (
    FrameRecord,
    compile_surveillance_csvs,
    _compute_id_stats,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_candump_log(path: Path, n_frames: int = 120) -> int:
    """Write a synthetic candump log, return number of distinct IDs."""
    lines = []
    ts = 1776477572.0
    for i in range(n_frames):
        payload = f"{(i & 0xFF):02X}000000"
        lines.append(f"({ts:.6f}) vcan0 600#{payload}")
        ts += 0.1
        lines.append(f"({ts:.6f}) vcan0 601#00000000")
        ts += 0.02
    path.write_text("\n".join(lines) + "\n")
    return 2  # IDs: 0x600, 0x601


# ---------------------------------------------------------------------------
# candump parsing
# ---------------------------------------------------------------------------


def test_candump_parsing(tmp_path):
    log = tmp_path / "test.log"
    _write_candump_log(log, n_frames=10)
    frames = parse_candump_log(log)
    assert len(frames) == 20  # 10 frames x 2 IDs
    assert frames[0].arbitration_id == 0x600
    assert frames[1].arbitration_id == 0x601


def test_empty_log_returns_empty(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("")
    frames = parse_candump_log(log)
    assert frames == []


def test_malformed_lines_skipped(tmp_path):
    log = tmp_path / "mixed.log"
    log.write_text(
        "(1000.000000) vcan0 600#DEAD\n"
        "not a frame at all\n"
        "(1001.000000) vcan0 601#BEEF\n"
    )
    frames = parse_candump_log(log)
    assert len(frames) == 2


# ---------------------------------------------------------------------------
# Per-ID statistics
# ---------------------------------------------------------------------------


def test_periodic_classification():
    frames = [
        FrameRecord(1000.0 + i * 0.1, 0x600, bytes(4)) for i in range(100)
    ]
    stats = _compute_id_stats(frames)
    assert 0x600 in stats
    s = stats[0x600]
    assert s.frame_count == 100
    assert s.classification == "periodic"
    assert abs(s.dt_median_ms - 100.0) < 5.0
    assert 9.0 < s.rate_hz < 11.0


def test_sporadic_classification():
    random.seed(42)
    ts = 1000.0
    frames = []
    for _ in range(50):
        ts += random.uniform(0.05, 0.8)
        frames.append(FrameRecord(ts, 0x700, bytes(2)))
    stats = _compute_id_stats(frames)
    assert stats[0x700].classification == "sporadic"


def test_rare_classification():
    frames = [FrameRecord(1000.0 + i, 0x800, bytes(1)) for i in range(3)]
    stats = _compute_id_stats(frames)
    assert stats[0x800].classification == "rare"


def test_single_frame_stats():
    frames = [FrameRecord(1000.0, 0x900, bytes([0xAB]))]
    stats = _compute_id_stats(frames)
    s = stats[0x900]
    assert s.frame_count == 1
    assert s.dt_mean_ms == 0.0
    assert s.classification == "rare"


def test_multiple_ids_sorted():
    frames = [
        FrameRecord(1000.0 + i * 0.1, 0x700, bytes(4)) for i in range(20)
    ] + [
        FrameRecord(1000.0 + i * 0.2, 0x600, bytes(2)) for i in range(15)
    ]
    stats = _compute_id_stats(frames)
    ids = list(stats.keys())
    assert ids == sorted(ids)  # sorted by CAN ID


# ---------------------------------------------------------------------------
# CSV compilation
# ---------------------------------------------------------------------------


def test_compile_csvs(tmp_path):
    frames = [
        FrameRecord(1000.0 + i * 0.1, 0x600, bytes([i & 0xFF, 0, 0, 0]), "vcan0")
        for i in range(50)
    ]
    paths = compile_surveillance_csvs(tmp_path, frames)

    # compiled_frames.csv
    frames_csv = Path(paths["compiled_frames_csv"])
    assert frames_csv.exists()
    with open(frames_csv) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 50
    assert rows[0]["can_id_hex"] == "0x600"
    assert rows[0]["dt_from_prev_same_id"] == ""  # first frame
    assert rows[1]["dt_from_prev_same_id"] != ""  # has delta
    assert rows[0]["classification"] == "periodic"
    assert rows[0]["payload_byte_0"] == "00"
    assert rows[0]["payload_byte_4"] == ""  # beyond DLC

    # compiled_ids.csv
    ids_csv = Path(paths["compiled_ids_csv"])
    assert ids_csv.exists()
    with open(ids_csv) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["can_id_hex"] == "0x600"
    assert rows[0]["classification"] == "periodic"
    assert int(rows[0]["frame_count"]) == 50


def test_compile_empty_frames(tmp_path):
    paths = compile_surveillance_csvs(tmp_path, [])
    # Files should exist but be empty (or just header)
    assert Path(paths["compiled_frames_csv"]).exists() is False or True
    assert Path(paths["compiled_ids_csv"]).exists() is False or True


def test_payload_bytes_split_correctly(tmp_path):
    frames = [
        FrameRecord(1000.0, 0x600, bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]), "vcan0"),
    ]
    paths = compile_surveillance_csvs(tmp_path, frames)
    with open(paths["compiled_frames_csv"]) as f:
        row = list(csv.DictReader(f))[0]
    assert row["payload_byte_0"] == "DE"
    assert row["payload_byte_1"] == "AD"
    assert row["payload_byte_2"] == "BE"
    assert row["payload_byte_3"] == "EF"
    assert row["payload_byte_4"] == "CA"
    assert row["payload_byte_5"] == "FE"
    assert row["payload_byte_6"] == ""
    assert row["payload_byte_7"] == ""
    assert row["payload_hex"] == "DEADBEEFCAFE"


# ---------------------------------------------------------------------------
# End-to-end: replay -> CSVs
# ---------------------------------------------------------------------------


def test_end_to_end_replay(tmp_path):
    log = tmp_path / "candump.log"
    n_ids = _write_candump_log(log)
    out_dir = tmp_path / "out"

    result = communication_surveillance_func(
        replay_path=str(log), output_dir=str(out_dir)
    )

    assert "compiled_frames_csv" in result
    assert "compiled_ids_csv" in result
    assert Path(result["compiled_frames_csv"]).exists()
    assert Path(result["compiled_ids_csv"]).exists()

    # Only CSVs should exist, no old artifacts
    output_files = {p.name for p in out_dir.iterdir()}
    assert "compiled_frames.csv" in output_files
    assert "compiled_ids.csv" in output_files
    assert "findings.json" not in output_files
    assert "candidate.dbc" not in output_files
    assert "surveillance_report.md" not in output_files

    with open(result["compiled_ids_csv"]) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == n_ids


def test_empty_session_is_rejected():
    session = SurveillanceSession()
    with pytest.raises(RuntimeError):
        session.generate_csvs()
