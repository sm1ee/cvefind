from __future__ import annotations

KNOWN_ALIASES: dict[tuple[str, str], set[str]] = {
    ("npm", "n8n"): {"n8n-io/n8n", "n8n.io"},
}


def get_aliases(ecosystem: str, package_name: str) -> set[str]:
    key = (ecosystem.lower(), package_name.lower())
    return set(KNOWN_ALIASES.get(key, set()))
