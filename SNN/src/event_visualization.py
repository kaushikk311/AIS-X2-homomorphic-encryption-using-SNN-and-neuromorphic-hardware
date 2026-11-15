from pathlib import Path
import matplotlib.pyplot as plt
# --------------------------------------------------
# 1. Project paths
# --------------------------------------------------
PROJECT_DIR = Path(__file__).resolve().parent.parent
TRAIN_DIR = PROJECT_DIR / "data" / "Train"
# --------------------------------------------------
# 2. Find an N-MNIST event file
# --------------------------------------------------
files = [
    f for f in TRAIN_DIR.rglob("*")
    if f.is_file()
]
if not files:
    print("ERROR: No event files found.")
    raise SystemExit
event_file = files[0]
print("Using file:")
print(event_file)
# --------------------------------------------------
# 3. Read binary event data
# --------------------------------------------------
with open(event_file, "rb") as f:
    raw_data = f.read()

EVENT_SIZE = 5
number_of_events = len(raw_data) // EVENT_SIZE
events = []
# --------------------------------------------------
# 4. Decode events
# --------------------------------------------------
for i in range(number_of_events):
    start = i * EVENT_SIZE
    end = start + EVENT_SIZE
    event_bytes = raw_data[start:end]
    value = int.from_bytes(
        event_bytes,
        byteorder="big"
    )
    # N-MNIST format:
    # bits 39-32 -> X
    # bits 31-24 -> Y
    # bit 23     -> Polarity
    # bits 22-0  -> Timestamp
    x = (value >> 32) & 0xFF
    y = (value >> 24) & 0xFF
    polarity = (value >> 23) & 0x01
    timestamp = value & 0x7FFFFF
    events.append(
        (x, y, polarity, timestamp)
    )
# --------------------------------------------------
# 5. Limit number of events
# --------------------------------------------------
MAX_EVENTS = 5000
events = events[:MAX_EVENTS]
# --------------------------------------------------
# 6. Separate event information
# --------------------------------------------------
x = [event[0] for event in events]
y = [event[1] for event in events]
polarity = [event[2] for event in events]
# --------------------------------------------------
# 7. Plot spikes
# --------------------------------------------------
plt.figure(figsize=(7, 7))
for i in range(len(events)):
    if polarity[i] == 1:
        plt.scatter(
            x[i],
            y[i],
            s=4,
            marker="o"
        )
    else:
        plt.scatter(
            x[i],
            y[i],
            s=4,
            marker="x"
        )
plt.title("N-MNIST Event / Spike Representation")
plt.xlabel("X position")
plt.ylabel("Y position")
plt.xlim(0, 34)
plt.ylim(34, 0)
plt.grid(True)
plt.show()
