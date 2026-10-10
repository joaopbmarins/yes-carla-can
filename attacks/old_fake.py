from collections import Counter, defaultdict
from statistics import median
import time
import can

def fake_data_fabrication_func(bus):
    print("Conducting I1 Fake Data Fabrication attack on CAN bus...")

    OBSERVATION_TIME = 5.0

    messages = defaultdict(lambda: {
        "count": 0,
        "last_timestamp": None,
        "periods": [],
        "payloads": []
    })

    try:
        start_time = time.time()

        while time.time() - start_time < OBSERVATION_TIME:
            message = bus.recv(timeout=0.5)

            if message is None:
                continue

            can_id = message.arbitration_id
            timestamp = message.timestamp
            payload = bytes(message.data)

            data = messages[can_id]
            data["count"] += 1
            data["payloads"].append(payload)

            # Calculate period since the previous message
            if data["last_timestamp"] is not None:
                period = timestamp - data["last_timestamp"]
                data["periods"].append(period)

            data["last_timestamp"] = timestamp

        print("\nMessage statistics:")

        # Sort by number of messages
        sorted_messages = sorted(
            messages.items(),
            key=lambda item: item[1]["count"],
            reverse=True
        )

        for can_id, data in sorted_messages:
            periods = data["periods"]
            payloads = data["payloads"]

            print(f"\n  ID=0x{can_id:X}")
            print(f"    count={data['count']}")

            # Average period
            if periods:
                average_period = sum(periods) / len(periods)

                print(
                    f"    average_period="
                    f"{average_period * 1000:.2f} ms"
                )

            # Highest payload value
            if payloads:
                highest_payload = max(
                    payloads,
                    key=lambda payload: int.from_bytes(
                        payload,
                        byteorder="little"
                    )
                )

                highest_value = int.from_bytes(
                    highest_payload,
                    byteorder="little"
                )

                print(
                    f"    highest_payload="
                    f"{highest_payload.hex(' ').upper()} "
                    f"(value={highest_value})"
                )

        # Most frequent CAN ID
        if sorted_messages:
            can_id, data = sorted_messages[0]

            print(
                f"\nMost frequent ID: "
                f"0x{can_id:X} ({data['count']} msgs)"
            )

    except KeyboardInterrupt:
        print("Fake Data Fabrication attack stopped by user.")

    except Exception as error:
        print(f"An error occurred: {error}")

    finally:
        try:
            bus.shutdown()
        except Exception:
            pass
