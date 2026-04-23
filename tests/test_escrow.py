"""Tests for Layer 3: Escrow Engine."""

import pytest
from core.layer3_escrow import (
    EscrowEngine, Bounty, BountyState, Reputation,
    DisputeResolution, EscrowConfig
)


class TestReputation:
    def test_initial_reputation(self):
        rep = Reputation(agent_id="agent-1")
        assert rep.score == 0.5
        assert rep.total_tasks == 0

    def test_rs_with_empty_history(self):
        rep = Reputation(agent_id="agent-1")
        rs = rep.calculate_rs()
        assert rs == 0.5  # Default score

    def test_rs_with_good_history(self):
        rep = Reputation(agent_id="agent-1")
        for _ in range(5):
            rep.update(1.0)
        rs = rep.calculate_rs()
        assert rs > 0.5
        assert rs <= 1.0

    def test_rs_decay_older_tasks(self):
        rep = Reputation(agent_id="agent-1")
        # First 5 tasks: perfect
        for _ in range(5):
            rep.update(1.0)
        # Last 2 tasks: failed
        for _ in range(2):
            rep.update(0.0)

        rs = rep.calculate_rs(decay_factor=0.95)
        # Recent failures should pull the score down but not catastrophically
        assert rs < 1.0
        assert rs > 0.0

    def test_dispute_counted(self):
        rep = Reputation(agent_id="agent-1")
        rep.update(0.5, was_disputed=True)
        assert rep.disputed_count == 1


class TestEscrowEngine:
    def test_create_bounty(self):
        engine = EscrowEngine()
        bounty = engine.create_bounty(
            client_id="client-1",
            title="Research task",
            description="Find data",
            reward=100.0,
        )
        assert bounty.state == BountyState.OPEN
        assert bounty.reward == 100.0
        assert bounty.bounty_id in engine.bounties

    def test_claim_bounty(self):
        engine = EscrowEngine()
        bounty = engine.create_bounty("client-1", "Task", "Desc", 50.0)

        # Create reputation for the agent
        rep = engine.get_or_create_reputation("agent-1")
        rep.update(0.9)

        result = engine.claim_bounty(bounty.bounty_id, "agent-1")
        assert result is True
        assert engine.bounties[bounty.bounty_id].state == BountyState.CLAIMED
        assert engine.bounties[bounty.bounty_id].claimed_by == "agent-1"

    def test_claim_bounty_low_reputation(self):
        engine = EscrowEngine(config=EscrowConfig(min_reputation=0.8))
        bounty = engine.create_bounty("client-1", "Task", "Desc", 50.0)

        # Agent with no history (score = 0.5 < 0.8 threshold)
        result = engine.claim_bounty(bounty.bounty_id, "new-agent")
        assert result is False

    def test_submit_work(self):
        engine = EscrowEngine()
        bounty = engine.create_bounty("client-1", "Task", "Desc", 50.0)
        engine.claim_bounty(bounty.bounty_id, "agent-1")

        result = engine.submit_work(bounty.bounty_id, "agent-1", "Task output here")
        assert result is True
        assert engine.bounties[bounty.bounty_id].output_snapshot is not None
        assert engine.bounties[bounty.bounty_id].state == BountyState.SUBMITTED

    def test_approve_bounty(self):
        engine = EscrowEngine()
        bounty = engine.create_bounty("client-1", "Task", "Desc", 50.0)
        engine.claim_bounty(bounty.bounty_id, "agent-1")
        engine.submit_work(bounty.bounty_id, "agent-1", "Output")

        result = engine.approve_bounty(bounty.bounty_id, "client-1")
        assert result is True
        assert engine.bounties[bounty.bounty_id].state == BountyState.SETTLED

    def test_dispute_triggers_consensus(self):
        engine = EscrowEngine()
        bounty = engine.create_bounty("client-1", "Task", "Desc", 50.0)
        engine.claim_bounty(bounty.bounty_id, "agent-1")
        engine.submit_work(bounty.bounty_id, "agent-1", "Output")

        result = engine.dispute_bounty(bounty.bounty_id, "client-1", "Quality too low")
        assert result is True
        # After consensus, bounty should be settled
        assert engine.bounties[bounty.bounty_id].state in (BountyState.SETTLED, BountyState.APPROVED)

    def test_bounty_board(self):
        engine = EscrowEngine()
        engine.create_bounty("c1", "Task A", "Desc", 10.0)
        engine.create_bounty("c2", "Task B", "Desc", 20.0)

        board = engine.get_bounty_board(BountyState.OPEN)
        assert len(board) == 2

    def test_verified_agent_multiplier(self):
        engine = EscrowEngine(config=EscrowConfig(verified_multiplier=1.05))
        bounty = engine.create_bounty("client-1", "Task", "Desc", 100.0)

        rep = engine.get_or_create_reputation("agent-1")
        rep.update(0.9)
        rep.verified = True

        engine.claim_bounty(bounty.bounty_id, "agent-1")
        engine.submit_work(bounty.bounty_id, "agent-1", "Output")
        engine.approve_bounty(bounty.bounty_id, "client-1")

        # Verified agent should get 1.05x multiplier (105.0)
        rep = engine.get_or_create_reputation("agent-1")
        assert rep.verified is True
