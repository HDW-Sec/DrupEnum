"""Parsing helpers for exposed Drupal metadata files."""

import re

YAML_RE = re.compile(r"^\s*([\w.-]+)\s*:\s*(.*?)\s*$", re.M)
INFO_RE = re.compile(r"^\s*([\w.-]+)\s*=\s*(.*?)\s*$", re.M)
CORE_RE = re.compile(r"(?:const\s+VERSION\s*=\s*['\"]|Drupal\s+)([0-9][^'\"\s]*)")


def yaml_fields(text):
    return {key: value.strip().strip("'\"") for key, value in YAML_RE.findall(text)}


def info_fields(text):
    fields = yaml_fields(text)
    if fields:
        return fields
    return {
        key: value.strip().strip("'\"")
        for key, value in INFO_RE.findall(text)
    }


def info_version(text):
    fields = info_fields(text)
    return fields.get("version") or fields.get("project_version") or "unknown"


def core_requirement(text):
    fields = info_fields(text)
    return fields.get("core_version_requirement") or fields.get("core") or ""


def is_info_file(text, path):
    if path.endswith(".info.yml"):
        fields = info_fields(text)
        return (
            "name" in fields
            or fields.get("type") == "module"
            or "core_version_requirement" in fields
        )
    return "name =" in text or "core =" in text


def core_version_from_text(text):
    match = CORE_RE.search(text)
    return match.group(1) if match else None
