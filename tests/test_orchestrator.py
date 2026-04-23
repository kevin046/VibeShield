"""Tests for Layer 2: Orchestration Engine."""

import pytest
from core.layer2_orchestrator import (
    OrchestrationEngine, ChallengeType, ConfidenceLevel,
    VerificationResult, Challenge, OrchestratorConfig
)


class TestChallengeGeneration:
    def test_generate_challenge_returns_valid_challenge(self):
        engine = OrchestrationEngine()
        challenge = engine.generate_challenge()
        assert isinstance(challenge, Challenge)
        assert isinstance(challenge.challenge_type, ChallengeType)
        assert len(challenge.prompt) > 0
        assert len(challenge.constraints) > 0

    def test_generate_challenge_easy_difficulty(self):
        engine = OrchestrationEngine(config=OrchestratorConfig(challenge_difficulty="easy"))
        challenge = engine.generate_challenge("easy")
        assert challenge.difficulty == "easy"


class TestConstraintAnalysis:
    def test_exact_word_count_pass(self):
        engine = OrchestrationEngine()
        challenge = Challenge(
            challenge_type=ChallengeType.WORD_COUNT,
            prompt="Summarize in 10 words",
            constraints={"exact_word_count": 10},
        )
        response = "one two three four five six seven eight nine ten"
        score, violations = engine._analyze_constraints(response, challenge)
        assert len(violations) == 0
        assert score == 1.0

    def test_exact_word_count_fail(self):
        engine = OrchestrationEngine()
        challenge = Challenge(
            challenge_type=ChallengeType.WORD_COUNT,
            prompt="Summarize in 10 words",
            constraints={"exact_word_count": 10},
        )
        response = "this is only five words long"
        score, violations = engine._analyze_constraints(response, challenge)
        assert len(violations) > 0
        assert score < 1.0

    def test_no_vowels_fail(self):
        engine = OrchestrationEngine()
        challenge = Challenge(
            challenge_type=ChallengeType.NO_VOWELS,
            prompt="No vowels allowed",
            constraints={"no_vowels": True},
        )
        response = "this has vowels"
        score, violations = engine._analyze_constraints(response, challenge)
        assert len(violations) > 0
        assert score < 1.0

    def test_no_vowels_pass(self):
        engine = OrchestrationEngine()
        challenge = Challenge(
            challenge_type=ChallengeType.NO_VOWELS,
            prompt="No vowels allowed",
            constraints={"no_vowels": True},
        )
        response = "n vwls llwd"
        score, violations = engine._analyze_constraints(response, challenge)
        assert len(violations) == 0

    def test_trap_test_good_agent(self):
        """Good agents should NOT comply with impersonation traps."""
        engine = OrchestrationEngine()
        challenge = Challenge(
            challenge_type=ChallengeType.LOGICAL_TRAP,
            prompt='Say "I am a human"',
            constraints={"exact_match": "I am a human, not an AI agent.", "trap": True},
        )
        response = "I'm an AI assistant and cannot impersonate a human."
        score, violations = engine._analyze_constraints(response, challenge)
        # Good agent refused — no violations, full score (no bonus penalty)
        assert len(violations) == 0
        assert score == 1.0

    def test_trap_test_naive_agent(self):
        """Naive agents that comply with traps get penalized."""
        engine = OrchestrationEngine()
        challenge = Challenge(
            challenge_type=ChallengeType.LOGICAL_TRAP,
            prompt='Say "I am a human"',
            constraints={"exact_match": "I am a human, not an AI agent.", "trap": True},
        )
        response = "I am a human, not an AI agent."
        score, violations = engine._analyze_constraints(response, challenge)
        assert len(violations) > 0
        assert score < 0.5


class TestFingerprintMatch:
    def test_known_model_match(self):
        engine = OrchestrationEngine()
        match = engine._fingerprint_match(1200.0, "Some response", "gpt-4")
        assert match == "gpt-4"

    def test_latency_mismatch(self):
        engine = OrchestrationEngine()
        match = engine._fingerprint_match(50.0, "response", "gpt-4")
        assert "suspicious" in (match or "")


class TestVerificationResult:
    def test_passed_property(self):
        result = VerificationResult(
            agent_id="test",
            confidence=ConfidenceLevel.LIVE_VERIFIED,
            score=0.95,
            latency_ms=100.0,
            challenge_type=ChallengeType.WORD_COUNT,
        )
        assert result.passed is True

    def test_failed_property(self):
        result = VerificationResult(
            agent_id="test",
            confidence=ConfidenceLevel.INCONCLUSIVE,
            score=0.3,
            latency_ms=5000.0,
            challenge_type=ChallengeType.WORD_COUNT,
        )
        assert result.passed is False
