import os
import glob

print("==============================================")
print("AIS-X2 : N-MNIST EVENT INSPECTION")
print("==============================================")

# Project root = one level above src
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Existing dataset
DATASET_FOLDER = os.path.join(PROJECT_ROOT, "data", "Train")

print("Dataset folder:")
print(DATASET_FOLDER)
print()

# Find .bin files
files = glob.glob(os.path.join(DATASET_FOLDER, "*", "*.bin"))

print("Files found:", len(files))
print()

if len(files) == 0:
    print("ERROR: No .bin files found!")
    print("Check that data\\Train contains class folders.")
    input("Press Enter to exit...")
    raise SystemExit

print("First few files:")

for f in files[:5]:
    print(f)

# Select first event file
selected_file = files[0]

print()
print("Selected file:")
print(selected_file)

# Read binary file
with open(selected_file, "rb") as f:
    raw_data = f.read()

print()
print("Raw file size:", len(raw_data), "bytes")

# Each event = 40 bits = 5 bytes
EVENT_SIZE = 5

num_events = len(raw_data) // EVENT_SIZE

print("Number of complete events:", num_events)

print()
print("==============================================")
print("FIRST 10 EVENTS")
print("==============================================")

for i in range(min(10, num_events)):

    start = i * EVENT_SIZE
    event_bytes = raw_data[start:start + EVENT_SIZE]

    # Convert 5 bytes into 40-bit integer
    event = int.from_bytes(event_bytes, byteorder="big")

    # Extract fields
    x = (event >> 32) & 0xFF
    y = (event >> 24) & 0xFF
    polarity = (event >> 23) & 0x01
    timestamp = event & 0x7FFFFF

    print(
        f"Event {i+1}: "
        f"X={x}, "
        f"Y={y}, "
        f"Polarity={polarity}, "
        f"Timestamp={timestamp} us"
    )

print()
print("==============================================")
print("EVENT STATISTICS")
print("==============================================")

x_values = []
y_values = []
polarities = []
timestamps = []

for i in range(num_events):

    start = i * EVENT_SIZE
    event_bytes = raw_data[start:start + EVENT_SIZE]

    event = int.from_bytes(event_bytes, byteorder="big")

    x = (event >> 32) & 0xFF
    y = (event >> 24) & 0xFF
    polarity = (event >> 23) & 0x01
    timestamp = event & 0x7FFFFF

    x_values.append(x)
    y_values.append(y)
    polarities.append(polarity)
    timestamps.append(timestamp)

print("X range          :", min(x_values), "to", max(x_values))
print("Y range          :", min(y_values), "to", max(y_values))
print("ON events        :", polarities.count(1))
print("OFF events       :", polarities.count(0))
print("Timestamp range  :", min(timestamps), "to", max(timestamps), "us")

print()
print("==============================================")
print("N-MNIST EVENT READING SUCCESSFUL")
print("==============================================")
