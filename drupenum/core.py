"""Drupal core detection and fingerprinting."""

import hashlib
import os
import re
import sqlite3
from urllib.parse import urljoin

import requests

from .config import CORE_FINGERPRINT_PATHS, CORE_MAJOR_CANDIDATES
from .http import make_session
from .parsing import core_version_from_text, yaml_fields

CORE_VERSION_PATHS = ("core/lib/Drupal.php", "CHANGELOG.txt", "core/CHANGELOG.txt")
EXPOSED_CONFIG_PATHS = (
    "sites/default/services.yml",
    "sites/default/default.services.yml",
    "sites/default/settings.yml",
    "sites/default/settings.php",
)


def detect_core(base_url, timeout, user_agent, insecure=False):
    core = {"version": "unknown", "source": "", "exposed_configs": []}
    session = make_session(user_agent, insecure)
    try:
        for path in CORE_VERSION_PATHS:
            try:
                response = session.get(
                    urljoin(base_url, path),
                    timeout=timeout,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue

            version = (
                core_version_from_text(response.text)
                if response.status_code == 200
                else None
            )
            if version:
                core.update(version=version, source="/" + path)
                break

        _detect_exposed_configs(core, session, base_url, timeout)
    finally:
        session.close()
    return core


def _detect_exposed_configs(core, session, base_url, timeout):
    for path in EXPOSED_CONFIG_PATHS:
        try:
            response = session.get(
                urljoin(base_url, path),
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            continue

        if response.status_code == 200 and response.text:
            core["exposed_configs"].append("/" + path)
            if core["version"] == "unknown":
                version = yaml_fields(response.text).get("version", "unknown")
                if version != "unknown":
                    core.update(version=version, source="/" + path)


def fingerprint_core(core, base_url, hash_db_path, timeout, user_agent, insecure=False):
    if not os.path.exists(hash_db_path):
        core["fingerprint_error"] = f"core hash DB not found: {hash_db_path}"
        return

    try:
        db = sqlite3.connect(hash_db_path)
    except sqlite3.Error as error:
        core["fingerprint_error"] = f"cannot open {hash_db_path}: {error}"
        return

    session = make_session(user_agent, insecure)
    fingerprints = []
    scores = {}
    matched_paths = {}
    try:
        for path in CORE_FINGERPRINT_PATHS:
            try:
                response = session.get(
                    urljoin(base_url, path),
                    timeout=timeout,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue
            if response.status_code != 200 or not response.content:
                continue

            fingerprint = _fingerprint_response(response.content)
            try:
                matches = _core_hash_matches(
                    db,
                    path,
                    fingerprint["sha256"],
                    fingerprint["size"],
                )
            except sqlite3.Error as error:
                core["fingerprint_error"] = f"invalid {hash_db_path}: {error}"
                return

            fingerprint.update(path="/" + path, matches=matches)
            fingerprints.append(fingerprint)
            for version in matches:
                scores[version] = scores.get(version, 0) + 1
                matched_paths.setdefault(version, []).append("/" + path)
    finally:
        session.close()
        db.close()

    if fingerprints:
        core["fingerprints"] = fingerprints
    _apply_fingerprint_estimates(core, scores, matched_paths)


def _fingerprint_response(content):
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "md5": hashlib.md5(content).hexdigest(),
        "size": len(content),
    }


def _core_hash_matches(db, path, sha256, size):
    return [
        row[0]
        for row in db.execute(
            """
            SELECT version
            FROM core_file_hashes
            WHERE path = ? AND sha256 = ? AND size = ?
            ORDER BY version
            """,
            (path, sha256, size),
        )
    ]


def _apply_fingerprint_estimates(core, scores, matched_paths):
    if not scores:
        return

    estimates = [
        {
            "version": version,
            "score": score,
            "matched_paths": matched_paths[version],
        }
        for version, score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    ]
    core["fingerprint_estimates"] = estimates
    if core["version"] == "unknown":
        best_score = estimates[0]["score"]
        core["estimated_versions"] = [
            item["version"] for item in estimates if item["score"] == best_score
        ]
        core["estimated_source"] = "static file fingerprints"


def core_requirement_candidates(requirement):
    candidates = set()
    for clause in re.split(r"\|\|", requirement):
        clause = clause.strip()
        if not clause:
            continue
        clause_candidates = set(CORE_MAJOR_CANDIDATES)
        matches = re.findall(r"(>=|>|<=|<|=|\^|~)?\s*(\d+)(?:\.\d+|\.x)?", clause)
        if not matches:
            continue
        for operator, major in matches:
            clause_candidates &= _filter_core_major_candidates(operator, int(major))
        candidates |= clause_candidates
    return candidates


def _filter_core_major_candidates(operator, major):
    if operator == ">=":
        return {candidate for candidate in CORE_MAJOR_CANDIDATES if candidate >= major}
    if operator == ">":
        return {candidate for candidate in CORE_MAJOR_CANDIDATES if candidate > major}
    if operator == "<=":
        return {candidate for candidate in CORE_MAJOR_CANDIDATES if candidate <= major}
    if operator == "<":
        return {candidate for candidate in CORE_MAJOR_CANDIDATES if candidate < major}
    return {major}


def infer_core_from_modules(core, modules):
    possible = None
    requirements = []
    for module in modules:
        requirement = module.get("core_version_requirement", "")
        candidates = core_requirement_candidates(requirement) if requirement else set()
        if not candidates:
            continue
        requirements.append(
            {
                "module": module["name"],
                "requirement": requirement,
                "candidates": [f"{version}.x" for version in sorted(candidates)],
            }
        )
        possible = candidates if possible is None else possible & candidates

    if requirements:
        core["core_version_requirements"] = requirements
    if core["version"] == "unknown" and possible:
        core["estimated_versions"] = [f"{version}.x" for version in sorted(possible)]
        core["estimated_source"] = "module core_version_requirement intersection"
