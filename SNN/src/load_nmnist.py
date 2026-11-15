from pathlib import Path


# --------------------------------------------------
# 1. Find project directories
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"
TRAIN_DIR = DATA_DIR / "Train"


print("=" * 60)
print("AIS-X2 : N-MNIST DATASET LOADER")
print("=" * 60)

print("Project folder :", PROJECT_DIR)
print("Dataset folder :", TRAIN_DIR)


# --------------------------------------------------
# 2. Find binary event files
# --------------------------------------------------

files = [
    f for f in TRAIN_DIR.rglob("*")
    if f.is_file()
]

print("\nFiles found:", len(files))

if len(files) == 0:
    print("\nERROR: No files were found inside the Train folder.")
    print("Check that the N-MNIST dataset was extracted correctly.")
    raise SystemExit


print("\nFirst few files:")

for f in files[:5]:
    print(" ", f)


# --------------------------------------------------
# 3. Select the first event file
# --------------------------------------------------

event_file = files[0]

print("\nSelected file:")
print(event_file)


# --------------------------------------------------
# 4. Read raw binary data
# --------------------------------------------------

with open(event_file, "rb") as f:
    raw_data = f.read()


print("\nRaw file size:", len(raw_data), "bytes")


# Each N-MNIST event occupies 40 bits = 5 bytes
EVENT_SIZE = 5

number_of_events = len(raw_data) // EVENT_SIZE

print("Number of complete events:", number_of_events)


# --------------------------------------------------
# 5. Decode N-MNIST events
# --------------------------------------------------

events = []

for i in range(number_of_events):

    start = i * EVENT_SIZE
    end = start + EVENT_SIZE

    event_bytes = raw_data[start:end]

    # Convert 5 bytes into one 40-bit integer
    value = int.from_bytes(
        event_bytes,
        byteorder="big"
    )

    # N-MNIST event format:
    #
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
# 6. Display first 10 events
# --------------------------------------------------

print("\n" + "=" * 60)
print("FIRST 10 EVENTS")
print("=" * 60)

for i, event in enumerate(events[:10]):

    x, y, polarity, timestamp = event

    print(
        f"Event {i + 1:2d}: "
        f"X={x:2d}, "
        f"Y={y:2d}, "
        f"Polarity={polarity}, "
        f"Timestamp={timestamp} us"
    )


# --------------------------------------------------
# 7. Basic statistics
# --------------------------------------------------

if events:

    x_values = [event[0] for event in events]
    y_values = [event[1] for event in events]
    polarities = [event[2] for event in events]
    timestamps = [event[3] for event in events]

    print("\n" + "=" * 60)
    print("EVENT STATISTICS")
    print("=" * 60)

    print(
        "X range         :",
        min(x_values),
        "to",
        max(x_values)
    )

    print(
        "Y range         :",
        min(y_values),
        "to",
        max(y_values)
    )

    print(
        "ON events       :",
        sum(p == 1 for p in polarities)
    )

    print(
        "OFF events      :",
        sum(p == 0 for p in polarities)
    )

    print(
        "Timestamp range :",
        min(timestamps),
        "to",
        max(timestamps),
        "us"
    )


print("\n" + "=" * 60)
print("N-MNIST EVENT READING SUCCESSFUL")
print("=" * 60)
