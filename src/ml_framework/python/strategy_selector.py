"""
Strategy Selector - Reinforcement Learning Agent for EDR Termination
Author: Karthik
Description: DQN agent that selects optimal attack techniques based on system state.
             SYNCED with ExploitManager (T1068, T1562.001, T1055.001, T1106).
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from collections import deque
import random
import json
from pathlib import Path


class DQNNetwork(nn.Module):
    def __init__(self, state_size, action_size, hidden_size=128):
        super(DQNNetwork, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(state_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size // 2, action_size),
        )

    def forward(self, x):
        return self.network(x)


class DQNAgent:
    # Inside class DQNAgent:
    def __init__(
        self, state_size=26, action_size=4, learning_rate=0.001
    ):  # Changed to 4
        self.state_size = state_size
        self.action_size = action_size
        self.gamma = 0.95
        self.epsilon = 1.0
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.learning_rate = learning_rate
        self.batch_size = 32
        self.memory = deque(maxlen=10000)

        self.policy_net = DQNNetwork(state_size, action_size)
        self.target_net = DQNNetwork(state_size, action_size)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=learning_rate)

        # STRICT MAPPING: Only your 4 actual C++ exploits
        self.action_names = [
            "BYOVD_VulnDriver",  # Action 0
            "EDR_Freeze_Thread",  # Action 1
            "Crystal_Palace_Loader",  # Action 2
            "SysWhispers4_Syscall",  # Action 3
        ]

    def select_action(self, state, valid_actions=None):
        if np.random.rand() <= self.epsilon:
            if valid_actions:
                return random.choice(valid_actions)
            return random.randint(0, self.action_size - 1)

        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0)
            q_values = self.policy_net(state_tensor)
            if valid_actions:
                q_values_np = q_values.numpy()[0]
                valid_q = {a: q_values_np[a] for a in valid_actions}
                return max(valid_q, key=valid_q.get)
            return torch.argmax(q_values).item()

    def remember(self, state, action, reward, next_state, done):
        self.memory.append((state, action, reward, next_state, done))

    def replay(self, batch_size=None):
        if batch_size is None:
            batch_size = self.batch_size
        if len(self.memory) < batch_size:
            return None

        minibatch = random.sample(self.memory, batch_size)
        states = torch.FloatTensor([e[0] for e in minibatch])
        actions = torch.LongTensor([e[1] for e in minibatch])
        rewards = torch.FloatTensor([e[2] for e in minibatch])
        next_states = torch.FloatTensor([e[3] for e in minibatch])
        dones = torch.FloatTensor([e[4] for e in minibatch])

        current_q = self.policy_net(states).gather(1, actions.unsqueeze(1))
        with torch.no_grad():
            max_next_q = self.target_net(next_states).max(1)[0]
            target_q = rewards + (1 - dones) * self.gamma * max_next_q

        loss = nn.MSELoss()(current_q.squeeze(), target_q)
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()

        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        return loss.item()

    def update_target_network(self):
        self.target_net.load_state_dict(self.policy_net.state_dict())

    def save(self, filepath):
        torch.save(
            {
                "policy_net_state": self.policy_net.state_dict(),
                "target_net_state": self.target_net.state_dict(),
                "optimizer_state": self.optimizer.state_dict(),
                "epsilon": self.epsilon,
            },
            filepath,
        )

    def load(self, filepath):
        checkpoint = torch.load(filepath)
        self.policy_net.load_state_dict(checkpoint["policy_net_state"])
        self.target_net.load_state_dict(checkpoint["target_net_state"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state"])
        self.epsilon = checkpoint["epsilon"]

    def get_action_name(self, action_id):
        return self.action_names[action_id]


# ============================================================================
# TESTING / DEMO CODE
# ============================================================================


def test_agent():
    """
    Basic test to verify agent works
    """
    print("=" * 60)
    print("Testing DQN Agent")
    print("=" * 60)

    agent = DQNAgent(state_size=26, action_size=4)

    # Dummy state (26 features, all zeros)
    state = np.zeros(26)
    state[0] = 1.0  # EDR running
    state[5] = 1.0  # PPL enabled

    print("\n1. Testing action selection...")
    action = agent.select_action(state)
    print(f"   Selected action: {action} ({agent.get_action_name(action)})")
    print(f"   Epsilon (exploration rate): {agent.epsilon:.3f}")

    print("\n2. Testing memory storage...")
    next_state = state.copy()
    next_state[0] = 0.0  # EDR terminated!
    agent.remember(state, action, reward=100, next_state=next_state, done=True)
    print(f"   Memory size: {len(agent.memory)}")

    print("\n3. Collecting more experiences...")
    for i in range(100):
        s = np.random.rand(26)
        a = random.randint(0, 3)
        r = random.choice([100, -50, 0, 50])
        s_next = np.random.rand(26)
        agent.remember(s, a, r, s_next, done=(r == 100))
    print(f"   Memory size: {len(agent.memory)}")

    print("\n4. Testing training (replay)...")
    loss = agent.replay(batch_size=32)
    print(f"   Loss: {loss:.4f}")
    print(f"   Epsilon after training: {agent.epsilon:.3f}")

    print("\n5. Testing save/load...")
    save_path = Path(__file__).parent.parent / "models" / "test_agent.pth"
    save_path.parent.mkdir(exist_ok=True)
    agent.save(save_path)

    new_agent = DQNAgent(state_size=26, action_size=4)
    new_agent.load(save_path)
    print(f"   Loaded epsilon: {new_agent.epsilon:.3f}")

    print("\n✓ All tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    test_agent()
