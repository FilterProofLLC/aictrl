"""Tests for execution adapter and boundary inspection commands.

CRITICAL: These tests verify that exec commands are INSPECTION ONLY.
- NEVER execute anything
- NEVER touch the OS
- NEVER call subprocesses
- Only report state derived from documentation
"""

import pytest
import inspect
import ast
from aictrl.commands.exec import (
    get_adapters_info,
    get_boundary_info,
    get_readiness_info,
)


class TestExecAdaptersInspectionOnly:
    """Tests for bbail exec adapters (inspection only)."""

    def test_adapters_returns_simulation_flag(self):
        """Adapters info must indicate simulation mode."""
        result = get_adapters_info()
        assert result["simulation"] is True

    def test_adapters_lists_adapter_types(self):
        """Adapters info must list adapter types."""
        result = get_adapters_info()
        assert "adapters" in result
        assert len(result["adapters"]) >= 3  # human, ci, external

    def test_adapters_includes_human_operator(self):
        """Human operator adapter must be defined."""
        result = get_adapters_info()
        types = [a["type"] for a in result["adapters"]]
        assert "human_operator" in types

    def test_adapters_includes_ci(self):
        """CI adapter must be defined."""
        result = get_adapters_info()
        types = [a["type"] for a in result["adapters"]]
        assert "ci" in types

    def test_adapters_includes_external(self):
        """External adapter must be defined."""
        result = get_adapters_info()
        types = [a["type"] for a in result["adapters"]]
        assert "external" in types

    def test_ai_adapter_prohibited(self):
        """AI adapter must be explicitly prohibited."""
        result = get_adapters_info()
        assert result["ai_adapter_allowed"] is False

    def test_ai_prohibition_explained(self):
        """AI prohibition must include explanation."""
        result = get_adapters_info()
        assert "ai_prohibition" in result
        assert result["ai_prohibition"]["no_exceptions"] is True

    def test_ai_prohibition_references_invariants(self):
        """AI prohibition must reference security invariants."""
        result = get_adapters_info()
        violations = result["ai_prohibition"]["invariant_violations"]
        # Must reference INV-004, INV-005, INV-007
        violations_text = " ".join(violations)
        assert "INV-004" in violations_text
        assert "INV-005" in violations_text
        assert "INV-007" in violations_text

    def test_adapters_includes_note(self):
        """Result must include inspection-only note."""
        result = get_adapters_info()
        assert "note" in result
        assert "inspection" in result["note"].lower()


class TestExecBoundaryInspectionOnly:
    """Tests for bbail exec boundary (inspection only)."""

    def test_boundary_returns_simulation_flag(self):
        """Boundary info must indicate simulation mode."""
        result = get_boundary_info()
        assert result["simulation"] is True

    def test_boundary_defines_simulation_barrier(self):
        """Simulation barrier must be defined."""
        result = get_boundary_info()
        assert "boundaries" in result
        assert "simulation_barrier" in result["boundaries"]

    def test_simulation_barrier_is_one_way(self):
        """Simulation barrier must be one-way."""
        result = get_boundary_info()
        barrier = result["boundaries"]["simulation_barrier"]
        assert barrier["properties"]["one_way"] is True

    def test_simulation_barrier_is_permanent(self):
        """Simulation barrier must be permanent."""
        result = get_boundary_info()
        barrier = result["boundaries"]["simulation_barrier"]
        assert barrier["properties"]["permanent"] is True

    def test_simulation_barrier_is_human_gated(self):
        """Simulation barrier must be human-gated."""
        result = get_boundary_info()
        barrier = result["boundaries"]["simulation_barrier"]
        assert barrier["properties"]["human_gated"] is True

    def test_simulation_barrier_is_non_automatable(self):
        """Simulation barrier must be non-automatable."""
        result = get_boundary_info()
        barrier = result["boundaries"]["simulation_barrier"]
        assert barrier["properties"]["non_automatable"] is True

    def test_boundary_defines_aios_responsibilities(self):
        """AIOS responsibilities must be defined."""
        result = get_boundary_info()
        assert "aios_responsibilities" in result["boundaries"]
        assert len(result["boundaries"]["aios_responsibilities"]) > 0

    def test_boundary_defines_aios_non_responsibilities(self):
        """AIOS non-responsibilities must be defined."""
        result = get_boundary_info()
        assert "aios_non_responsibilities" in result["boundaries"]
        # AIOS is NOT responsible for actual execution
        non_resp = result["boundaries"]["aios_non_responsibilities"]
        assert "actual_execution" in non_resp

    def test_boundary_defines_operator_responsibilities(self):
        """Operator responsibilities must be defined."""
        result = get_boundary_info()
        assert "operator_responsibilities" in result["boundaries"]
        assert len(result["boundaries"]["operator_responsibilities"]) > 0

    def test_trust_does_not_propagate(self):
        """Trust must not propagate across boundary."""
        result = get_boundary_info()
        assert result["trust_propagation"] == "none"

    def test_ai_cannot_cross_boundary(self):
        """AI must not be able to cross boundary."""
        result = get_boundary_info()
        assert result["ai_can_cross"] is False

    def test_boundary_includes_note(self):
        """Result must include inspection-only note."""
        result = get_boundary_info()
        assert "note" in result
        assert "inspection" in result["note"].lower()


class TestExecReadinessInspectionOnly:
    """Tests for bbail exec readiness (inspection only)."""

    def test_readiness_returns_simulation_flag(self):
        """Readiness info must indicate simulation mode."""
        result = get_readiness_info()
        assert result["simulation"] is True

    def test_readiness_accepts_request_id(self):
        """Readiness must accept optional request ID."""
        result = get_readiness_info(request_id="test-123")
        assert result["request_id"] == "test-123"

    def test_readiness_defaults_request_id_to_none(self):
        """Readiness must handle missing request ID."""
        result = get_readiness_info()
        assert result["request_id"] == "none"

    def test_readiness_checks_authorization(self):
        """Readiness must check authorization status."""
        result = get_readiness_info()
        assert "authorization" in result["readiness"]
        assert result["readiness"]["authorization"]["required"] is True

    def test_readiness_checks_invariants(self):
        """Readiness must check invariant status."""
        result = get_readiness_info()
        assert "invariants" in result["readiness"]
        assert result["readiness"]["invariants"]["required"] is True

    def test_readiness_checks_acknowledgement(self):
        """Readiness must check acknowledgement status."""
        result = get_readiness_info()
        assert "acknowledgement" in result["readiness"]
        assert result["readiness"]["acknowledgement"]["required"] is True
        assert result["readiness"]["acknowledgement"]["level_required"] >= 3

    def test_readiness_not_ready_by_default(self):
        """Readiness must report not ready in simulation."""
        result = get_readiness_info()
        assert result["ready_for_crossing"] is False

    def test_readiness_lists_blockers(self):
        """Readiness must list blockers."""
        result = get_readiness_info()
        assert "blockers" in result
        assert len(result["blockers"]) > 0

    def test_readiness_includes_note(self):
        """Result must include inspection-only note."""
        result = get_readiness_info()
        assert "note" in result
        assert "inspection" in result["note"].lower()


class TestNoExecutionPaths:
    """Tests proving no execution paths exist in exec commands."""

    def test_get_adapters_info_no_execution_calls(self):
        """get_adapters_info must not call subprocess or os execution."""
        source = inspect.getsource(get_adapters_info)
        # Check for actual execution calls (not docstring mentions)
        assert "subprocess.run" not in source
        assert "subprocess.call" not in source
        assert "subprocess.Popen" not in source
        assert "os.system(" not in source
        assert "os.popen(" not in source

    def test_get_boundary_info_no_execution_calls(self):
        """get_boundary_info must not call subprocess or os execution."""
        source = inspect.getsource(get_boundary_info)
        # Check for actual execution calls (not docstring mentions)
        assert "subprocess.run" not in source
        assert "subprocess.call" not in source
        assert "subprocess.Popen" not in source
        assert "os.system(" not in source
        assert "os.popen(" not in source

    def test_get_readiness_info_no_execution_calls(self):
        """get_readiness_info must not call subprocess or os execution."""
        source = inspect.getsource(get_readiness_info)
        # Check for actual execution calls (not docstring mentions)
        assert "subprocess.run" not in source
        assert "subprocess.call" not in source
        assert "subprocess.Popen" not in source
        assert "os.system(" not in source
        assert "os.popen(" not in source

    def test_exec_module_no_dangerous_imports(self):
        """exec module inspection functions must not import dangerous modules.

        Note: Phase 15 location enforcement (run_proposal only) is allowed
        to use subprocess for git commands, but inspection functions must
        remain pure.
        """
        # Check the inspection functions themselves, not the whole module
        # Phase 15 adds location enforcement which uses subprocess for git
        # but that's only in run_proposal, not inspection functions
        for func in [get_adapters_info, get_boundary_info, get_readiness_info]:
            source = inspect.getsource(func)

            # Must not import subprocess
            assert "import subprocess" not in source
            assert "from subprocess" not in source

            # Must not import os.system
            assert "os.system" not in source
            assert "os.popen" not in source
            assert "os.spawn" not in source

            # Must not import shutil (for rmtree, etc.)
            assert "import shutil" not in source

    def test_adapters_info_pure_data(self):
        """get_adapters_info must return pure data (no side effects)."""
        # Call twice, must return identical results
        result1 = get_adapters_info()
        result2 = get_adapters_info()
        assert result1 == result2

    def test_boundary_info_pure_data(self):
        """get_boundary_info must return pure data (no side effects)."""
        # Call twice, must return identical results
        result1 = get_boundary_info()
        result2 = get_boundary_info()
        assert result1 == result2

    def test_readiness_info_deterministic(self):
        """get_readiness_info must be deterministic."""
        # Same input must produce same output
        result1 = get_readiness_info(request_id="test")
        result2 = get_readiness_info(request_id="test")
        assert result1 == result2


class TestGovernanceCompliance:
    """Tests verifying governance compliance."""

    def test_adapters_prohibits_ai_adapter(self):
        """AI as adapter must be prohibited per INV-004."""
        result = get_adapters_info()
        assert result["ai_adapter_allowed"] is False
        # No AI adapter type in list
        for adapter in result["adapters"]:
            assert adapter["type"] != "ai"
            assert "artificial_intelligence" not in adapter["type"].lower()

    def test_boundary_requires_human_acknowledgement(self):
        """Boundary crossing must require human acknowledgement per INV-005."""
        result = get_boundary_info()
        requires = result["boundaries"]["simulation_barrier"]["requires"]
        assert "human_acknowledgement" in requires

    def test_readiness_requires_authorization(self):
        """Readiness must require authorization per Phase 9."""
        result = get_readiness_info()
        assert result["readiness"]["authorization"]["required"] is True

    def test_readiness_requires_invariants(self):
        """Readiness must require invariant check per Phase 4."""
        result = get_readiness_info()
        assert result["readiness"]["invariants"]["required"] is True

    def test_boundary_evidence_generating(self):
        """Boundary crossing must generate evidence per Phase 5."""
        result = get_boundary_info()
        barrier = result["boundaries"]["simulation_barrier"]
        assert barrier["properties"]["evidence_generating"] is True

    def test_all_adapters_require_acknowledgement(self):
        """All adapters must require acknowledgement."""
        result = get_adapters_info()
        for adapter in result["adapters"]:
            assert adapter.get("requires_acknowledgement", False) is True


class TestCLIIntegration:
    """Tests for CLI command integration."""

    def test_exec_adapters_callable(self):
        """exec adapters command must be callable."""
        from aictrl.cli import cmd_exec_adapters

        class MockArgs:
            pretty = True

        result = cmd_exec_adapters(MockArgs())
        assert result == 0  # EXIT_SUCCESS

    def test_exec_boundary_callable(self):
        """exec boundary command must be callable."""
        from aictrl.cli import cmd_exec_boundary

        class MockArgs:
            pretty = True

        result = cmd_exec_boundary(MockArgs())
        assert result == 0  # EXIT_SUCCESS

    def test_exec_readiness_callable(self):
        """exec readiness command must be callable."""
        from aictrl.cli import cmd_exec_readiness

        class MockArgs:
            pretty = True
            request_id = None

        result = cmd_exec_readiness(MockArgs())
        assert result == 0  # EXIT_SUCCESS
