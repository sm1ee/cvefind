from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer

from cvefind.service import find_cves

SUMMARY_MAX_LEN = 250

SEVERITY_COLOR = {
    "critical": None,
    "high": typer.colors.BRIGHT_RED,
    "medium": typer.colors.YELLOW,
    "moderate": typer.colors.YELLOW,
    "low": typer.colors.GREEN,
    "unknown": typer.colors.WHITE,
}


def _truncate_summary(value: Optional[str], max_len: int = SUMMARY_MAX_LEN) -> Optional[str]:
    if not value:
        return None
    clean = " ".join(value.split())
    if len(clean) <= max_len:
        return clean
    return clean[: max_len - 3].rstrip() + "..."


def _normalize_display_severity(value: Optional[str]) -> str:
    raw = (value or "unknown").strip().lower()
    if raw == "moderate":
        raw = "medium"
    return raw


def _severity_badge(value: Optional[str]) -> str:
    severity = _normalize_display_severity(value)
    label = severity.capitalize()
    if severity == "critical":
        # ANSI 256 slightly bright dark-red tone.
        colored = f"\033[1;38;5;124m{label}\033[0m"
        return f"[{colored}]"
    color = SEVERITY_COLOR.get(severity, typer.colors.WHITE)
    colored = typer.style(label, fg=color, bold=True)
    return f"[{colored}]"


def _pick_ghsa_link(references: Optional[list[str]]) -> Optional[str]:
    if not references:
        return None
    for url in references:
        if "github.com/advisories/GHSA-" in url:
            return url
    return None


def _build_nvd_link(cve_id: Optional[str]) -> Optional[str]:
    if not cve_id:
        return None
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _cvss_version_label(cvss_vector: Optional[str]) -> Optional[str]:
    if not cvss_vector:
        return None
    vector = cvss_vector.strip().upper()
    if vector.startswith("CVSS:3.1/"):
        return "v3.1"
    if vector.startswith("CVSS:3.0/"):
        return "v3.0"
    if vector.startswith("CVSS:4.0/"):
        return "v4.0"
    if vector.startswith("AV:"):
        return "v2.0"
    return None


def _render_human(result: dict) -> str:
    lines: list[str] = []
    header = typer.style(
        f"cvefind | {result['ecosystem']}:{result['package']}",
        fg=typer.colors.CYAN,
        bold=True,
    )
    lines.append(header)
    if result.get("aliases_used"):
        lines.append(
            f"{typer.style('aliases', fg=typer.colors.BLUE, bold=True)}: {', '.join(result['aliases_used'])}"
        )
    severity_header = _normalize_display_severity(result.get("min_severity") or "all")
    lines.append(
        f"{typer.style('severity', fg=typer.colors.BLUE, bold=True)}: {severity_header}"
    )
    lines.append(
        f"{typer.style('cves', fg=typer.colors.BLUE, bold=True)}: {result['count']}"
    )
    lines.append("")

    cves = result.get("cves", [])
    if cves:
        lines.append(typer.style("CVEs (newest first)", fg=typer.colors.GREEN, bold=True))
        for item in cves:
            badge = _severity_badge(item.get("severity"))
            cvss_score = item.get("cvss_score")
            cvss_part = ""
            if isinstance(cvss_score, (float, int)):
                cvss_version = _cvss_version_label(item.get("cvss_vector"))
                if cvss_version:
                    cvss_part = f" (CVSS{cvss_version} {float(cvss_score):.1f})"
                else:
                    cvss_part = f" (CVSS {float(cvss_score):.1f})"
            lines.append(f"{badge} {item['cve_id']}{cvss_part}")
            summary = _truncate_summary(item.get("summary"))
            if summary:
                lines.append(f"Summary: {summary}")
            ghsa_link = _pick_ghsa_link(item.get("references"))
            nvd_link = _build_nvd_link(item.get("cve_id"))
            if ghsa_link:
                lines.append(f" ⤷ GHSA: {ghsa_link}")
            if nvd_link:
                lines.append(f" ⤷ NVD: {nvd_link}")
            lines.append("")
    else:
        lines.append(typer.style("CVEs: none", fg=typer.colors.YELLOW, bold=True))

    pending = result.get("pending_ghsa", [])
    if pending:
        lines.append("")
        pending_count = result.get("pending_ghsa_count", len(pending))
        lines.append(
            typer.style(
                f"Pending GHSA (no CVE yet): {pending_count}",
                fg=typer.colors.MAGENTA,
                bold=True,
            )
        )
        for item in pending:
            badge = _severity_badge(item.get("severity"))
            ghsa_label = typer.style(item["ghsa_id"], fg=typer.colors.MAGENTA, bold=True)
            lines.append(f"{badge} {ghsa_label}")
            summary = _truncate_summary(item.get("summary"))
            if summary:
                lines.append(f"Summary: {summary}")
            ghsa_link = _pick_ghsa_link(item.get("references"))
            if ghsa_link:
                lines.append(f" ⤷ GHSA: {ghsa_link}")
            lines.append("")

    if result.get("errors"):
        lines.append("")
        lines.append(typer.style("Source errors", fg=typer.colors.YELLOW, bold=True))
        for source, err in sorted(result["errors"].items()):
            source_label = typer.style(source, fg=typer.colors.YELLOW, bold=True)
            lines.append(f"- {source_label}: {err}")
    return "\n".join(lines)


def main(
    package_name: str = typer.Argument(..., help="Package name. Example: n8n"),
    ecosystem: str = typer.Option("npm", "--ecosystem", "-e", help="Package ecosystem"),
    alias: list[str] = typer.Option(
        None,
        "--alias",
        "-a",
        help="Additional search alias. Repeatable.",
    ),
    include_ghsa_pending: bool = typer.Option(
        False,
        "--include-ghsa-pending",
        help="Include GHSA advisories that do not have a CVE yet.",
    ),
    min_severity: Optional[str] = typer.Option(
        None,
        "--min-severity",
        help="Filter by minimum severity: low, medium, moderate, high, critical.",
    ),
    output: str = typer.Option(
        "default",
        "--output",
        "-o",
        help="Output format: default, json, yaml.",
    ),
    timeout: float = typer.Option(20.0, "--timeout", help="HTTP timeout (seconds)"),
) -> None:
    result = asyncio.run(
        find_cves(
            package_name=package_name,
            ecosystem=ecosystem,
            extra_aliases=alias or [],
            include_ghsa_pending=include_ghsa_pending,
            min_severity=min_severity,
            timeout_sec=timeout,
        )
    )
    output_key = output.strip().lower()
    if output_key == "default":
        typer.echo(_render_human(result))
        return
    if output_key == "json":
        typer.echo(json.dumps(result, indent=2, ensure_ascii=False))
        return
    if output_key == "yaml":
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise typer.BadParameter(
                "YAML output requires PyYAML. Install with: pip install pyyaml"
            ) from exc
        typer.echo(yaml.safe_dump(result, sort_keys=False, allow_unicode=True))
        return
    raise typer.BadParameter("Unsupported output format. Use: default, json, yaml.")


def run() -> None:
    typer.run(main)


if __name__ == "__main__":
    run()
