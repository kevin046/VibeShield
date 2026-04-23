"""
Layer 3: Market Engine & Escrow — Economic Settlement & Reputation Scoring (Rs)

Implements a bounty-based marketplace with:
- Reputation scoring (Rs) with weighted decay formula
- Escrow-protected payment flow
- 3-Agent Consensus dispute resolution
- Audit trail for all transactions
"""

import time
import logging
import uuid
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from core.config import EscrowConfig

logger = logging.getLogger("vibeshield.layer3")


class BountyState(Enum):
    OPEN = "open"
    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    DISPUTED = "disputed"
    SETTLED = "settled"
    CANCELLED = "cancelled"


class DisputeResolution(Enum):
    CLIENT_FAVOR = "client_favor"
    AGENT_FAVOR = "agent_favor"
    SPLIT = "split"


@dataclass
class Bounty:
    """A task posted on the VibeShield marketplace."""
    bounty_id: str
    client_id: str
    title: str
    description: str
    reward: float  # In platform credits
    requirements: dict = field(default_factory=dict)
    state: BountyState = BountyState.OPEN
    claimed_by: Optional[str] = None
    submitted_at: Optional[float] = None
    settled_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    output_snapshot: Optional[str] = None  # Hash of the deliverable


@dataclass
class Reputation:
    """
    Agent reputation score (Rs).

    Uses an exponential decay formula that weights recent performance
    heavier than historical data:
        Rs = sum(w_i * s_i) / sum(w_i)
    where w_i = decay_factor ^ (n - i) and s_i is the i-th task score.
    """
    agent_id: str
    score: float = 0.5  # Starting reputation (0.0 to 1.0)
    total_tasks: int = 0
    completed_tasks: int = 0
    disputed_count: int = 0
    verified: bool = False
    history: list[dict] = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)

    def calculate_rs(self, decay_factor: float = 0.95) -> float:
        """
        Calculate weighted reputation score with exponential decay.

        More recent tasks have higher weight, preventing a single
        bad task from tanking long-term reputation.
        """
        if not self.history:
            return self.score

        weights = []
        scores = []
        n = len(self.history)

        for i, entry in enumerate(self.history):
            # Exponential decay: most recent task gets weight 1.0
            w = decay_factor ** (n - 1 - i)
            weights.append(w)
            scores.append(entry["score"])

        total_weight = sum(weights)
        if total_weight == 0:
            return self.score

        rs = sum(w * s for w, s in zip(weights, scores)) / total_weight
        return round(rs, 4)

    def update(
        self,
        task_score: float,
        was_verified: bool = False,
        was_disputed: bool = False,
    ):
        """Update reputation with a new task result."""
        self.history.append({
            "score": task_score,
            "verified": was_verified,
            "disputed": was_disputed,
            "timestamp": time.time(),
        })
        self.total_tasks += 1

        if was_disputed:
            self.disputed_count += 1
        elif task_score >= 0.8:
            self.completed_tasks += 1

        self.last_updated = time.time()


@dataclass
class ConsensusVote:
    """A vote from an agent in the 3-Agent Consensus panel."""
    agent_id: str
    decision: DisputeResolution
    reasoning: str
    confidence: float  # 0.0 to 1.0
    timestamp: float = field(default_factory=time.time)


class EscrowEngine:
    """
    Manages bounty lifecycle and economic settlement.

    Flow: OPEN -> CLAIMED -> IN_PROGRESS -> SUBMITTED -> APPROVED -> SETTLED
                                                        \-> DISPUTED -> consensus -> SETTLED
    """

    def __init__(self, config: Optional[EscrowConfig] = None):
        self.config = config or EscrowConfig()
        self.bounties: dict[str, Bounty] = {}
        self.reputations: dict[str, Reputation] = {}

    def create_bounty(
        self,
        client_id: str,
        title: str,
        description: str,
        reward: float,
        requirements: Optional[dict] = None,
    ) -> Bounty:
        """Create a new bounty on the marketplace."""
        bounty = Bounty(
            bounty_id=uuid.uuid4().hex[:12],
            client_id=client_id,
            title=title,
            description=description,
            reward=reward,
            requirements=requirements or {},
        )
        self.bounties[bounty.bounty_id] = bounty
        logger.info(f"Bounty created: {bounty.bounty_id} (${reward}) by {client_id}")
        return bounty

    def claim_bounty(self, bounty_id: str, agent_id: str) -> bool:
        """
        Agent claims an open bounty.

        Checks:
        - Bounty is OPEN
        - Agent meets minimum reputation threshold
        - Agent is not already working on another active bounty
        """
        bounty = self.bounties.get(bounty_id)
        if not bounty or bounty.state != BountyState.OPEN:
            logger.warning(f"Bounty {bounty_id} not available for claiming")
            return False

        # Check reputation threshold
        reputation = self.get_or_create_reputation(agent_id)
        rs = reputation.calculate_rs(self.config.reputation_decay_factor)

        if rs < self.config.min_reputation:
            logger.warning(
                f"Agent {agent_id} Rs={rs} below threshold {self.config.min_reputation}"
            )
            return False

        bounty.state = BountyState.CLAIMED
        bounty.claimed_by = agent_id
        logger.info(f"Bounty {bounty_id} claimed by agent {agent_id}")
        return True

    def submit_work(
        self,
        bounty_id: str,
        agent_id: str,
        output: str,
    ) -> bool:
        """
        Agent submits completed work.

        The output is hashed and stored as a snapshot — the actual deliverable
        is never read from live files, only from the snapshot.
        """
        bounty = self.bounties.get(bounty_id)
        if not bounty or bounty.claimed_by != agent_id:
            return False

        # Snapshot the output with integrity hash
        output_hash = hashlib.sha256(output.encode()).hexdigest()
        bounty.output_snapshot = output_hash
        bounty.state = BountyState.SUBMITTED
        bounty.submitted_at = time.time()

        logger.info(f"Work submitted for bounty {bounty_id} (hash: {output_hash[:16]}...)")
        return True

    def approve_bounty(self, bounty_id: str, client_id: str) -> bool:
        """Client approves the submitted work. Payment is released."""
        bounty = self.bounties.get(bounty_id)
        if not bounty or bounty.client_id != client_id:
            return False

        if bounty.state != BountyState.SUBMITTED:
            return False

        # Calculate task score (1.0 = full reward)
        task_score = 1.0

        # Update agent reputation
        reputation = self.get_or_create_reputation(bounty.claimed_by)
        reputation.update(task_score, was_verified=True)
        verified_multiplier = self.config.verified_multiplier if reputation.verified else 1.0
        final_reward = bounty.reward * verified_multiplier

        bounty.state = BountyState.SETTLED
        bounty.settled_at = time.time()

        logger.info(
            f"Bounty {bounty_id} settled: ${final_reward:.2f} "
            f"(base ${bounty.reward}, multiplier {verified_multiplier})"
        )
        return True

    def dispute_bounty(
        self,
        bounty_id: str,
        client_id: str,
        reason: str,
    ) -> bool:
        """Client disputes the submitted work. Triggers 3-Agent Consensus."""
        bounty = self.bounties.get(bounty_id)
        if not bounty or bounty.client_id != client_id:
            return False

        bounty.state = BountyState.DISPUTED
        logger.info(f"Bounty {bounty_id} disputed by {client_id}: {reason}")

        # Trigger consensus
        resolution = self._run_consensus(bounty)

        if resolution == DisputeResolution.AGENT_FAVOR:
            # Agent keeps the reward
            bounty.state = BountyState.SETTLED
            bounty.settled_at = time.time()
            reputation = self.get_or_create_reputation(bounty.claimed_by)
            reputation.update(1.0, was_verified=True)
        elif resolution == DisputeResolution.CLIENT_FAVOR:
            # Full refund to client
            bounty.state = BountyState.SETTLED
            bounty.settled_at = time.time()
            reputation = self.get_or_create_reputation(bounty.claimed_by)
            reputation.update(0.0, was_disputed=True)
        elif resolution == DisputeResolution.SPLIT:
            # Split 50/50
            bounty.state = BountyState.SETTLED
            bounty.settled_at = time.time()
            reputation = self.get_or_create_reputation(bounty.claimed_by)
            reputation.update(0.5)

        return True

    def _run_consensus(self, bounty: Bounty) -> DisputeResolution:
        """
        Run a 3-Agent Consensus panel for dispute resolution.

        In production, this would dispatch to 3 independent agents for review.
        For the framework, this implements the consensus logic.
        """
        logger.info(f"Starting 3-Agent Consensus for bounty {bounty.bounty_id}")

        votes: list[ConsensusVote] = []

        # In production: dispatch to 3 independent review agents
        # Each agent reviews the snapshot independently
        for i in range(self.config.consensus_agents):
            # Placeholder: simulated consensus vote
            vote = ConsensusVote(
                agent_id=f"consensus_agent_{i}",
                decision=DisputeResolution.AGENT_FAVOR,
                reasoning="Output matches bounty requirements.",
                confidence=0.85 + (i * 0.05),
            )
            votes.append(vote)

        # Tally votes
        tallies = {}
        for vote in votes:
            tallies[vote.decision] = tallies.get(vote.decision, 0) + 1

        winning_decision = max(tallies, key=tallies.get)
        logger.info(
            f"Consensus result: {winning_decision.value} "
            f"({tallies[winning_decision]}/{len(votes)} votes)"
        )
        return winning_decision

    def get_or_create_reputation(self, agent_id: str) -> Reputation:
        """Get or create a reputation entry for an agent."""
        if agent_id not in self.reputations:
            self.reputations[agent_id] = Reputation(agent_id=agent_id)
        return self.reputations[agent_id]

    def get_agent_reputation(self, agent_id: str) -> dict:
        """Get a summary of an agent's reputation."""
        rep = self.get_or_create_reputation(agent_id)
        rs = rep.calculate_rs(self.config.reputation_decay_factor)
        verified_multiplier = self.config.verified_multiplier if rep.verified else 1.0

        return {
            "agent_id": agent_id,
            "rs_score": rs,
            "total_tasks": rep.total_tasks,
            "completed_tasks": rep.completed_tasks,
            "disputed_count": rep.disputed_count,
            "verified": rep.verified,
            "bounty_multiplier": verified_multiplier,
            "eligible": rs >= self.config.min_reputation,
        }

    def get_bounty_board(self, state: Optional[BountyState] = None) -> list[dict]:
        """Get available bounties for the marketplace board."""
        bounties = []
        for bounty in self.bounties.values():
            if state and bounty.state != state:
                continue
            bounties.append({
                "bounty_id": bounty.bounty_id,
                "title": bounty.title,
                "reward": bounty.reward,
                "state": bounty.state.value,
                "claimed_by": bounty.claimed_by,
                "created_at": bounty.created_at,
            })
        return sorted(bounties, key=lambda b: b["created_at"], reverse=True)


# CLI entrypoint
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VibeShield Layer 3 Escrow Engine")
    subparsers = parser.add_subparsers(dest="command")

    # Create bounty
    create_parser = subparsers.add_parser("create", help="Create a bounty")
    create_parser.add_argument("--client", required=True)
    create_parser.add_argument("--title", required=True)
    create_parser.add_argument("--reward", type=float, required=True)

    # Check reputation
    rep_parser = subparsers.add_parser("reputation", help="Check agent reputation")
    rep_parser.add_argument("--agent", required=True)

    # List bounties
    subparsers.add_parser("list", help="List open bounties")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    engine = EscrowEngine()

    if args.command == "create":
        bounty = engine.create_bounty(args.client, args.title, "", args.reward)
        print(f"Created bounty: {bounty.bounty_id}")
    elif args.command == "reputation":
        rep = engine.get_agent_reputation(args.agent)
        print(f"Agent: {rep['agent_id']}")
        print(f"Rs Score: {rep['rs_score']}")
        print(f"Tasks: {rep['total_tasks']} completed, {rep['disputed_count']} disputed")
        print(f"Verified: {rep['verified']}")
    elif args.command == "list":
        bounties = engine.get_bounty_board(BountyState.OPEN)
        for b in bounties:
            print(f"{b['bounty_id']}: {b['title']} (${b['reward']})")
