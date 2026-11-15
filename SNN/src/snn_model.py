import torch
import torch.nn as nn

from spikingjelly.activation_based import neuron
from spikingjelly.activation_based import functional


class AISX2SNN(nn.Module):

    def __init__(self, num_classes=10):

        super().__init__()

        self.network = nn.Sequential(

            nn.Conv2d(
                in_channels=2,
                out_channels=16,
                kernel_size=3,
                padding=1
            ),

            nn.BatchNorm2d(16),

            neuron.IFNode(),

            nn.MaxPool2d(2),

            nn.Conv2d(
                in_channels=16,
                out_channels=32,
                kernel_size=3,
                padding=1
            ),

            nn.BatchNorm2d(32),

            neuron.IFNode(),

            nn.MaxPool2d(2),

            nn.Flatten(),
            nn.Dropout(0.3),

            nn.Linear(
                32 * 8 * 8,
                128
            ),

            neuron.IFNode(),

            nn.Linear(
                128,
                num_classes
            )
        )


    def forward(self, x):

        # x shape:
        # [time, batch, channels, height, width]

        functional.reset_net(self.network)

        outputs = []

        for t in range(x.shape[0]):

            output = self.network(x[t])

            outputs.append(output)

        return torch.stack(outputs)
