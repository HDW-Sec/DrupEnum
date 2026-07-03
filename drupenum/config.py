"""Shared defaults for DrupEnum."""

from importlib.resources import files
from pathlib import Path


def _default_data_path(filename):
    repo_path = Path(__file__).resolve().parent.parent / filename
    if repo_path.exists():
        return str(repo_path)
    return str(files("drupenum.data").joinpath(filename))


PROBE_THREADS = 10
DEFAULT_DB_NAME = "drupal_modules.sqlite"
DEFAULT_CORE_HASH_DB_NAME = "drupal_core_hashes.sqlite"
DEFAULT_DB = _default_data_path(DEFAULT_DB_NAME)
DEFAULT_CORE_HASH_DB = _default_data_path(DEFAULT_CORE_HASH_DB_NAME)
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

CORE_FINGERPRINT_PATHS = (
    "core/misc/drupal.js",
    "core/misc/ajax.js",
    "core/misc/states.js",
    "core/misc/once.js",
    "core/misc/tabbingmanager.js",
    "core/themes/claro/css/base/elements.css",
    "core/themes/claro/css/components/messages.css",
    "core/themes/olivero/css/base/base.css",
    "core/themes/olivero/css/components/header.css",
)

CORE_MAJOR_CANDIDATES = set(range(7, 13))
