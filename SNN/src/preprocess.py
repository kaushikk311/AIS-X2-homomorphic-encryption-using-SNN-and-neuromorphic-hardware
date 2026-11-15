import os
import glob
import numpy as np

print("==============================================")
print("AIS-X2 : N-MNIST EVENT PREPROCESSING")
print("==============================================")

# Project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Training dataset
DATASET_FOLDER = os.path.join(PROJECT_ROOT, "data", "Train")

# Find event files
files = glob.glob(os.path.join(DATASET_FOLDER, "*", "*.bin"))

print("Dataset folder:")
print(DATASET_FOLDER)

print()
print("Total event files:", len(files))

if len(files) == 0:
    print("ERROR: No N-MNIST files found!")
    raise SystemExit

# Use one sample first
selected_file = files[0]

print()
print("Processing:")
print(selected_file)

# Read raw binary data
with open(selected_file, "rb") as f:
    raw_data = f.read()

# Each event = 5 bytes = 40 bits
EVENT_SIZE = 5

num_events = len(raw_data) // EVENT_SIZE

# Arrays for event information
x = np.zeros(num_events, dtype=np.int16)
y = np.zeros(num_events, dtype=np.int16)
polarity = np.zeros(num_events, dtype=np.int8)
timestamp = np.zeros(num_events, dtype=np.int64)

# Decode events
for i in range(num_events):

    start = i * EVENT_SIZE

    event_bytes = raw_data[start:start + EVENT_SIZE]

    event = int.from_bytes(event_bytes, byteorder="big")

    x[i] = (event >> 32) & 0xFF
    y[i] = (event >> 24) & 0xFF
    polarity[i] = (event >> 23) & 0x01
    timestamp[i] = event & 0x7FFFFF

print()
print("Decoded events:", num_events)

print()
print("Event arrays:")
print("X shape         :", x.shape)
print("Y shape         :", y.shape)
print("Polarity shape  :", polarity.shape)
print("Timestamp shape :", timestamp.shape)

# Convert timestamps into relative time
timestamp = timestamp - timestamp[0]

print()
print("Time starts at  :", timestamp[0], "us")
print("Time ends at    :", timestamp[-1], "us")

# Create a simple time-bin representation
NUM_TIME_BINS = 20

max_time = timestamp[-1]

if max_time == 0:
    max_time = 1

time_bins = np.linspace(0, max_time, NUM_TIME_BINS + 1)

# Tensor:
# [time, polarity, y, x]
event_tensor = np.zeros(
    (NUM_TIME_BINS, 2, 34, 34),
    dtype=np.uint8
)

# Put each event into its time bin
for i in range(num_events):

    t = np.searchsorted(time_bins, timestamp[i], side="right") - 1

    if t >= NUM_TIME_BINS:
        t = NUM_TIME_BINS - 1

    px = x[i]
    py = y[i]
    p = polarity[i]

    if 0 <= px < 34 and 0 <= py < 34:
        event_tensor[t, p, py, px] = 1

print()
print("==============================================")
print("PREPROCESSED EVENT TENSOR")
print("==============================================")

print("Tensor shape:", event_tensor.shape)

print()
print("Meaning:")
print("Time bins :", NUM_TIME_BINS)
print("Polarity  : 2 (OFF / ON)")
print("Height    : 34")
print("Width     : 34")

print()
print("Non-zero events:", np.count_nonzero(event_tensor))

print()
print("N-MNIST PREPROCESSING SUCCESSFUL")
print("==============================================")
