from copy import deepcopy

import torch
from torch import nn


class TinyClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(4, 8), nn.ReLU(), nn.Linear(8, 2))

    def forward(self, x):
        return self.net(x)


def local_train(model, data, labels, epochs=2):
    model = deepcopy(model)
    opt = torch.optim.SGD(model.parameters(), lr=0.05)
    loss_fn = nn.CrossEntropyLoss()
    for _ in range(epochs):
        opt.zero_grad()
        loss = loss_fn(model(data), labels)
        loss.backward()
        opt.step()
    return model.state_dict()


def fedavg(states):
    out = {}
    for key in states[0]:
        out[key] = sum(s[key] for s in states) / len(states)
    return out


def main(rounds=3):
    server = TinyClassifier()
    clients = [torch.randn(12, 4) for _ in range(3)]
    labels = [torch.randint(0, 2, (12,)) for _ in range(3)]

    for r in range(rounds):
        local_states = []
        for i in range(3):
            local_states.append(local_train(server, clients[i], labels[i]))
        server.load_state_dict(fedavg(local_states))
        print(f"Round {r+1}: aggregation complete")


if __name__ == "__main__":
    main()
