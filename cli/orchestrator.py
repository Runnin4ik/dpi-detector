"""Алиас для обратной совместимости: функционал перенесён в app.orchestrator."""

from app.orchestrator import (
    fetch_network_panel,
    execute_test_suite,
    run_orchestrator_loop,
)

__all__ = [
    "execute_test_suite",
    "fetch_network_panel",
    "run_orchestrator_loop",
]
