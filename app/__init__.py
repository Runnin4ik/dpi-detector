"""Модули приложения DPI Detector: аргументы, баннеры, меню и оркестрация."""

from app.args import (
    parse_arguments,
    setup_logging,
    fast_exit_handler,
    check_dependencies,
)
from app.banner import (
    CURRENT_VERSION,
    GITHUB_REPO,
    render_banner,
    version_badge,
    header_render,
    header_height,
    fetch_latest_version,
    init_header_state,
)
from app.menu import (
    handle_legend_menu,
    prompt_test_selection,
)
from app.orchestrator import (
    fetch_network_panel,
    execute_test_suite,
    run_orchestrator_loop,
)

__all__ = [
    "CURRENT_VERSION",
    "GITHUB_REPO",
    "check_dependencies",
    "execute_test_suite",
    "fast_exit_handler",
    "fetch_latest_version",
    "fetch_network_panel",
    "handle_legend_menu",
    "header_height",
    "header_render",
    "init_header_state",
    "parse_arguments",
    "prompt_test_selection",
    "render_banner",
    "run_orchestrator_loop",
    "setup_logging",
    "version_badge",
]
