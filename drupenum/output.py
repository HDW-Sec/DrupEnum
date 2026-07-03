"""Human-readable CLI output."""

import os
import sys


_RESET = "\033[0m"
_STYLES = {
    "title": "\033[1;36m",
    "section": "\033[1m",
    "label": "\033[36m",
    "success": "\033[32m",
    "warning": "\033[33m",
    "danger": "\033[31m",
    "muted": "\033[2m",
}


def print_text(core, modules, color="auto"):
    color_enabled = _use_color(color)
    print()
    print(_style("=== Drupal enum results ===", "title", color_enabled))
    _print_core(core, color_enabled)
    _print_modules(modules, color_enabled)


def _use_color(color):
    if color in (False, "never"):
        return False
    if color in (True, "always"):
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _style(text, style, color_enabled):
    if not color_enabled:
        return text
    return f"{_STYLES[style]}{text}{_RESET}"


def _print_core(core, color_enabled):
    print()
    print(_style("Core", "section", color_enabled))
    _print_field("Version", core["version"], color_enabled, _version_style(core["version"]))
    _print_field("Source", core["source"], color_enabled)
    if core.get("estimated_versions"):
        _print_field(
            "Estimate",
            f"{', '.join(core['estimated_versions'])} ({core['estimated_source']})",
            color_enabled,
            "warning",
        )
    if core["exposed_configs"]:
        _print_field(
            "Exposed cfg",
            ", ".join(core["exposed_configs"]),
            color_enabled,
            "warning",
        )
    if core.get("fingerprint_error"):
        _print_field("Fingerprint", core["fingerprint_error"], color_enabled, "danger")
    elif core.get("fingerprint_estimates"):
        preview = ", ".join(
            f"{item['version']}({item['score']})"
            for item in core["fingerprint_estimates"][:5]
        )
        _print_field("Fingerprint", preview, color_enabled, "warning")
    _print_vulns("Core vulns", core.get("vulns", []), color_enabled)


def _print_modules(modules, color_enabled):
    print()
    print(
        f"{_style('Modules found', 'section', color_enabled)}: "
        f"{_style(str(len(modules)), 'success', color_enabled)}"
    )
    _print_module_table(modules, color_enabled)
    for module in modules:
        package_vulns = _without_exact_vulns(module)
        if not module.get("vulns") and not package_vulns:
            continue
        print()
        name = _style(module["name"], "section", color_enabled)
        version = _style(module["version"], "success", color_enabled)
        print(f"{name} ({version})")
        _print_vulns("Matching version", module.get("vulns", []), color_enabled, indent="  ")
        _print_vulns("Package history", package_vulns, color_enabled, indent="  ")


def _print_module_table(modules, color_enabled):
    if not modules:
        print(_style("No exposed modules found.", "muted", color_enabled))
        return

    name_width = min(max(6, max(len(module["name"]) for module in modules)), 34)
    version_width = min(max(7, max(len(module["version"]) for module in modules)), 18)
    header = (
        f"{'Module':{name_width}}  "
        f"{'Version':{version_width}}  "
        f"{'Vulns':20}  Path"
    )
    print(_style(header, "label", color_enabled))
    print(_style("-" * len(header), "muted", color_enabled))
    for module in modules:
        status = _compact_vuln_status(module)
        status_style = _status_style(status)
        name = f"{module['name']:{name_width}.{name_width}}"
        version = f"{module['version']:{version_width}.{version_width}}"
        status = f"{status:20.20}"
        print(
            f"{_style(name, status_style, color_enabled)}  "
            f"{_style(version, _version_style(module['version']), color_enabled)}  "
            f"{_style(status, status_style, color_enabled)}  "
            f"{_style(module['path'], 'muted', color_enabled)}"
        )


def _print_field(label, value, color_enabled, value_style=None):
    if value:
        label = _style(f"{label:<13}", "label", color_enabled)
        if value_style:
            value = _style(value, value_style, color_enabled)
        print(f"  {label} {value}")


def _print_vulns(title, vulns, color_enabled, indent="  "):
    if not vulns:
        return
    print(f"{indent}{_style(title, 'danger', color_enabled)}:")
    for vuln in vulns:
        summary = _compact_summary(vuln.get("summary", ""))
        vuln_id = _style(vuln["id"], "danger", color_enabled)
        print(f"{indent} - {vuln_id} -> {vuln['url']}")
        if summary:
            print(f"{indent}   {_style(summary, 'warning', color_enabled)}")


def _compact_vuln_status(item):
    exact = len(item.get("vulns", []))
    history = len(_without_exact_vulns(item))
    parts = []
    if exact:
        parts.append(f"vuln:{exact}")
    if history:
        parts.append(f"history:{history}")
    return ", ".join(parts) if parts else "-"


def _status_style(status):
    if status.startswith("vuln:"):
        return "danger"
    if status != "-":
        return "warning"
    return "success"


def _version_style(version):
    return "warning" if version == "unknown" else "success"


def _without_exact_vulns(item):
    exact_ids = {vuln["id"] for vuln in item.get("vulns", [])}
    return [
        vuln
        for vuln in item.get("package_vulns", [])
        if vuln["id"] not in exact_ids
    ]


def _compact_summary(text, limit=96):
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[:limit - 3].rstrip() + "..."
