"""Утилиты версионирования и сравнения semver."""

import re


def is_newer(latest: str, current: str) -> bool:
    """Semver-сравнение: latest > current. Устойчив к 'v', prerelease-суффиксам и мусору."""
    try:
        def parse(v: str) -> tuple:
            clean = v.lstrip("vV").strip()
            main_ver = re.split(r"[-+]", clean)[0]
            parts = []
            for part in main_ver.split("."):
                m = re.match(r"^\d+", part)
                if m:
                    parts.append(int(m.group(0)))
            while len(parts) < 3:
                parts.append(0)
            return tuple(parts)

        p_lat = parse(latest)
        p_cur = parse(current)
        if not any(p_lat) or not any(p_cur):
            return False
        return p_lat > p_cur
    except Exception:
        return False
