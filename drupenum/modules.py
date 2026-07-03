"""Drupal module candidate loading and probing."""

import concurrent.futures as futures
import sqlite3
from urllib.parse import urljoin

import requests

from .http import make_session
from .parsing import core_requirement, info_version, is_info_file


def load_db_modules(path):
    try:
        with sqlite3.connect(path) as db:
            return {
                row[0]
                for row in db.execute("SELECT name FROM modules ORDER BY name")
            }
    except sqlite3.Error:
        return set()


def load_file_modules(path):
    modules = set()
    with open(path, encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if line and not line.startswith("#"):
                modules.add(line.split()[0])
    return modules


def module_candidates(modules_file=None, db_path=None):
    modules = set()
    if modules_file:
        modules |= load_file_modules(modules_file)
    if db_path:
        modules |= load_db_modules(db_path)
    return modules


def module_paths(name):
    return (
        f"modules/contrib/{name}/{name}.info.yml",
        f"modules/{name}/{name}.info.yml",
        f"profiles/contrib/{name}/{name}.info.yml",
        f"sites/all/modules/contrib/{name}/{name}.info",
        f"sites/all/modules/{name}/{name}.info",
    )


def probe_module(name, base_url, timeout, user_agent, insecure=False):
    session = make_session(user_agent, insecure)
    try:
        for path in module_paths(name):
            try:
                response = session.get(
                    urljoin(base_url, path),
                    timeout=timeout,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue

            if response.status_code == 200 and is_info_file(response.text, path):
                return {
                    "name": name,
                    "version": info_version(response.text),
                    "core_version_requirement": core_requirement(response.text),
                    "path": "/" + path,
                    "vulns": [],
                    "package_vulns": [],
                }
    finally:
        session.close()
    return None


def enumerate_modules(
    module_names,
    base_url,
    timeout,
    user_agent,
    insecure=False,
    max_workers=10,
    on_found=None,
):
    found = []
    with futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        jobs = (
            pool.submit(
                probe_module,
                name,
                base_url,
                timeout,
                user_agent,
                insecure,
            )
            for name in module_names
        )
        for job in futures.as_completed(jobs):
            result = job.result()
            if result:
                found.append(result)
                if on_found:
                    on_found(result)
    return sorted(found, key=lambda module: module["name"])
