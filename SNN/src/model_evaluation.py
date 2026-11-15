import torch
import tonic
from snn_model import AISX2SNN
from preprocess import preprocess_events


print("=" * 60)
print("AIS-X2 : SNN MODEL EVALUATION")
print("=" * 60)

# Load test dataset
dataset = tonic.datasets.NMNIST(
    save_to="../data",
    train=False
)

# Create model
model = AISX2SNN()
model.eval()

correct = 0
total = 20

print("\nTesting first", total, "samples...\n")

for i in range(total):

    events, label = dataset[i]

    # Preprocess event data
    tensor = preprocess_events(events)

    # Add batch dimension
    tensor = tensor.unsqueeze(1)

    # SNN prediction
    with torch.no_grad():
        output = model(tensor)

    prediction = output.sum(dim=0).argmax(dim=1).item()

    if prediction == label:
        correct += 1

    print(
        "Sample:", i + 1,
        "| Actual:", label,
        "| Predicted:", prediction,
        "|", "CORRECT" if prediction == label else "WRONG"
    )

accuracy = (correct / total) * 100

print("\n" + "=" * 60)
print("RESULT")
print("=" * 60)
print("Correct :", correct)
print("Total   :", total)
print("Accuracy:", accuracy, "%")
print("=" * 60)
