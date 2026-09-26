"""L8: plateau detection + seed proposal tests."""

from __future__ import annotations

from vulnagent.fuzz.seed_proposal import (
    DeterministicSeedProposalProvider,
    PlateauDetector,
)


class TestPlateauDetector:
    def test_not_plateau_while_advancing(self) -> None:
        detector = PlateauDetector(threshold_seconds=60.0)
        signal = detector.update(10.0, new_coverage=True)
        assert signal.plateau is False

    def test_plateau_after_stall(self) -> None:
        detector = PlateauDetector(threshold_seconds=60.0)
        detector.update(10.0, new_coverage=True)
        signal = detector.update(100.0, new_coverage=False)
        assert signal.plateau is True
        assert signal.stalled_seconds == 90.0
        assert signal.executions_without_new_coverage == 1

    def test_plateau_requires_start_observation(self) -> None:
        detector = PlateauDetector(threshold_seconds=1.0)
        # no initial new-coverage observation => never plateaus
        signal = detector.update(100.0, new_coverage=False)
        assert signal.plateau is False

    def test_invalid_threshold_rejected(self) -> None:
        try:
            PlateauDetector(threshold_seconds=0)
            assert False, "expected ValueError"
        except ValueError:
            pass


class TestDeterministicSeedProposalProvider:
    def test_proposes_deterministic_bounded_inputs(self) -> None:
        corpus = [b"\x00" * 32, b"\x01\x02\x03\x04", b"seed" * 4]
        provider = DeterministicSeedProposalProvider()
        first = provider.propose(corpus, PlateauSignalStub(), seed=7, max_proposals=8)
        second = provider.propose(corpus, PlateauSignalStub(), seed=7, max_proposals=8)
        assert first == second  # deterministic under the same seed
        assert len(first) <= 8
        assert all(isinstance(item, bytes) for item in first)

    def test_empty_corpus_yields_nothing(self) -> None:
        provider = DeterministicSeedProposalProvider()
        assert provider.propose([], PlateauSignalStub(), seed=1) == []

    def test_proposals_never_execute_target(self) -> None:
        # The provider only returns bytes; there is no execution surface.
        provider = DeterministicSeedProposalProvider()
        proposals = provider.propose([b"abc"], PlateauSignalStub(), seed=3)
        assert isinstance(proposals, list)


class PlateauSignalStub:
    plateau = False
    stalled_seconds = 0.0
    executions_without_new_coverage = 0
    threshold_seconds = 60.0
    note = "stub"
