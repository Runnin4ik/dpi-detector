"""Алиас для обратной совместимости: функционал перенесён в app.banner."""

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

__all__ = [
    "CURRENT_VERSION",
    "GITHUB_REPO",
    "fetch_latest_version",
    "header_height",
    "header_render",
    "init_header_state",
    "render_banner",
    "version_badge",
]
