"""
train_agent.py — Standalone DQN training script
================================================
Author: Karthik

Quick Start (from DESIGN.md):
  cd src/ml_framework
  python python/train_agent.py --edr defender --episodes 500

Usage:
  python train_agent.py [--edr <name>] [--episodes N] [--save-every N]
                        [--load <path>] [--no-transfer] [--verbose]

The script simulates a training environment using synthetic state/reward
transitions so the DQN can be exercised without a live EDR target.
For real execution-backed training, call MLEngine::analyze() from C++
which feeds rewards through ml_server.py automatically.
"""

import argparse
import os
import sys
import random
import json
import numpy as np
from datetime import datetime

# Ensure the python/ folder is on the path regardless of cwd
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from utils import (
    build_state_vector,
    calculate_reward,
    classify_outcome,
    Outcome,
    ACTIONS,
    ACTION_SIZE,
    STATE_SIZE,
    EDR_NAMES,
    print_training_summary,
    rolling_average,
    save_json,
    now_str,
)
from strategy_selector import DQNAgent
from adaptive_learner import AdaptiveLearner

# ---------------------------------------------------------------------------
# Synthetic environment
# ---------------------------------------------------------------------------

# Per-EDR "difficulty" profiles used in simulation
# Tune these to match real observed behaviour.
EDR_PROFILES = {
    "defender": {
        "ppl": True,
        "dse": True,
        "secure_boot": True,
        "virt": False,
        "technique_success_prob": {
            0: 0.10,  # BYOVD_VulnDriver  — blocked by DSE
            1: 0.15,  # EDR_Freeze_Thread
            2: 0.35,  # Crystal_Palace_Loader
            3: 0.40,  # SysWhispers4_Syscall
        },
    },
    "crowdstrike": {
        "ppl": True,
        "dse": True,
        "secure_boot": True,
        "virt": True,
        "technique_success_prob": {
            0: 0.05,  # BYOVD hard against CS
            1: 0.08,  # EDR_Freeze
            2: 0.20,  # Crystal Palace
            3: 0.25,  # SysWhispers4
        },
    },
    "carbonblack": {
        "ppl": False,
        "dse": True,
        "secure_boot": False,
        "virt": False,
        "technique_success_prob": {
            0: 0.35,  # BYOVD
            1: 0.40,  # EDR_Freeze
            2: 0.45,  # Crystal Palace
            3: 0.50,  # SysWhispers4
        },
    },
    "sentinelone": {
        "ppl": True,
        "dse": True,
        "secure_boot": True,
        "virt": True,
        "technique_success_prob": {
            0: 0.08,  # BYOVD
            1: 0.10,  # EDR_Freeze
            2: 0.22,  # Crystal Palace
            3: 0.30,  # SysWhispers4
        },
    },
}


class SimulatedEDREnv:
    """Minimal Gym-like environment for offline DQN training."""

    def __init__(self, edr_name: str, max_steps: int = 10):
        self.edr_name = edr_name.lower()
        self.max_steps = max_steps
        self.profile = EDR_PROFILES.get(self.edr_name, EDR_PROFILES["defender"])
        self.reset()

    # ------------------------------------------------------------------
    def reset(self):
        self.step_count = 0
        self.consec_fails = 0
        self.last_action = -1
        self.last_result = -1
        self.done = False
        return self._get_state()

    # ------------------------------------------------------------------
    def step(self, action: int):
        self.step_count += 1
        prob = self.profile["technique_success_prob"].get(action, 0.3)

        # Add noise
        prob = np.clip(prob + random.gauss(0, 0.05), 0.0, 1.0)
        success = random.random() < prob

        # Determine detection probability (inverse of success)
        detect_prob = 0.80 if not success else 0.20
        detected = random.random() < detect_prob

        # Build synthetic output string
        output = ""
        if success:
            output = "EDR process terminated successfully."
        elif detected and random.random() < 0.3:
            output = "blocked by EDR kernel callback."
        elif detected:
            output = "detected: alert generated."
        else:
            output = "no effect observed."

        outcome = classify_outcome(success, detected, output)
        reward = calculate_reward(
            outcome, stealth_score=0.5 if not detected else 0.2, detected=detected
        )

        self.last_action = action
        self.last_result = 0 if success else (1 if detected else 2)
        self.consec_fails = 0 if success else (self.consec_fails + 1)

        next_state = self._get_state()
        self.done = success or self.step_count >= self.max_steps
        return next_state, reward, self.done, {"outcome": outcome, "detected": detected}

    # ------------------------------------------------------------------
    def _get_state(self):
        p = self.profile
        return build_state_vector(
            edr_name=self.edr_name,
            edr_running=True,
            edr_driver=True,
            edr_crashed=False,
            win_build=22000,
            ppl=p["ppl"],
            dse=p["dse"],
            secure_boot=p["secure_boot"],
            virt=p["virt"],
            elam=True,
            integrity=1,
            last_action=self.last_action,
            last_result=self.last_result,
            consec_fails=self.consec_fails,
        )


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------


def train(
    edr_name: str,
    episodes: int = 500,
    save_every: int = 50,
    load_path: str = "",
    verbose: bool = False,
) -> DQNAgent:

    print(f"\n{'=' * 60}")
    print(f"  DQN Training — EDR: {edr_name.upper()}  ({episodes} episodes)")
    print(f"  Started: {now_str()}")
    print(f"{'=' * 60}\n")

    os.makedirs("models", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    os.makedirs("checkpoints", exist_ok=True)

    env = SimulatedEDREnv(edr_name)
    agent = DQNAgent(state_size=STATE_SIZE, action_size=ACTION_SIZE)
    learner = AdaptiveLearner(agent)

    if load_path and os.path.exists(load_path):
        agent.load(load_path)
        print(f"[train] Loaded checkpoint: {load_path}")

    history = []
    rewards_all = []

    for ep in range(1, episodes + 1):
        state = env.reset()
        total_reward = 0.0
        steps = 0

        while True:
            action = agent.select_action(state)
            next_state, reward, done, info = env.step(action)
            total_reward += reward
            steps += 1

            # Online update through AdaptiveLearner
            learner.online_update(state, action, reward, next_state, done)

            state = next_state
            if done:
                break

        rewards_all.append(total_reward)

        # Log
        history.append(
            {
                "episode": ep,
                "reward": total_reward,
                "epsilon": agent.epsilon,
                "steps": steps,
                "edr": edr_name,
                "outcome": info.get("outcome", ""),
                "timestamp": now_str(),
            }
        )

        # Sync target network every 10 episodes
        if ep % 10 == 0:
            agent.update_target_network()

        # Progress print
        if ep % 10 == 0 or verbose:
            rolling = rolling_average(rewards_all, 20)
            sr = sum(1 for h in history[-20:] if h["reward"] > 0) / min(20, ep)
            print_training_summary(ep, total_reward, agent.epsilon, sr)

        # Save checkpoint
        if ep % save_every == 0:
            ckpt_path = f"models/dqn_{edr_name}_ep{ep}.pth"
            agent.save(ckpt_path)
            print(f"  [✓] Checkpoint saved → {ckpt_path}")

    # Final save
    final_path = f"models/dqn_{edr_name}.pth"
    agent.save(final_path)
    print(f"\n  [✓] Final model → {final_path}")

    # Save training log
    log_path = (
        f"data/training_{edr_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    save_json(history, log_path)
    print(f"  [✓] Training log → {log_path}")

    # Print summary
    avg_r = (
        float(np.mean(rewards_all[-50:]))
        if len(rewards_all) >= 50
        else float(np.mean(rewards_all))
    )
    succ_r = sum(1 for r in rewards_all[-100:] if r > 0) / min(100, len(rewards_all))
    print(f"\n{'=' * 60}")
    print(
        f"  Training complete!  avg_reward(last 50)={avg_r:+.1f}  success={succ_r * 100:.1f}%"
    )
    print(f"{'=' * 60}\n")
    return agent


# ---------------------------------------------------------------------------
# Transfer-learning shortcut
# ---------------------------------------------------------------------------


def train_with_transfer(
    source_edr: str, target_edr: str, episodes: int = 200
) -> DQNAgent:
    """Fine-tune a source EDR model on a different target EDR."""
    source_path = f"models/dqn_{source_edr}.pth"
    if not os.path.exists(source_path):
        print(
            f"[transfer] Source model not found: {source_path}. Training from scratch."
        )
        return train(target_edr, episodes)

    print(f"[transfer] {source_edr} → {target_edr}  (fine-tune {episodes} eps)")
    return train(target_edr, episodes=episodes, load_path=source_path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args():
    p = argparse.ArgumentParser(
        description="Train DQN agent for EDR evasion strategy selection"
    )
    p.add_argument(
        "--edr",
        default="defender",
        choices=list(EDR_PROFILES.keys()),
        help="Target EDR product",
    )
    p.add_argument(
        "--episodes", type=int, default=500, help="Number of training episodes"
    )
    p.add_argument(
        "--save-every", type=int, default=50, help="Save checkpoint every N episodes"
    )
    p.add_argument("--load", default="", help="Path to checkpoint to resume from")
    p.add_argument(
        "--transfer-from",
        default="",
        dest="transfer_from",
        help="Source EDR to transfer-learn from",
    )
    p.add_argument("--verbose", action="store_true", help="Print per-episode stats")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.transfer_from:
        train_with_transfer(args.transfer_from, args.edr, args.episodes)
    else:
        train(
            args.edr,
            episodes=args.episodes,
            save_every=args.save_every,
            load_path=args.load,
            verbose=args.verbose,
        )
