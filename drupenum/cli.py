"""Command-line interface for DrupEnum."""

import argparse
import json
import sys
import time

from .config import DEFAULT_CORE_HASH_DB, DEFAULT_DB, PROBE_THREADS, USER_AGENT
from .core import detect_core, fingerprint_core, infer_core_from_modules
from .http import normalize_target_url
from .modules import enumerate_modules, load_db_modules, load_file_modules
from .osv import check_vulns
from .output import print_text


def main(argv=None):
    args = parse_args(argv)
    base_url = normalize_target_url(args.target)
    started = time.monotonic()

    log(f"[*] target: {base_url}")
    core = detect_core(base_url, args.timeout, args.user_agent, args.insecure)
    module_names = load_candidates(args)
    if not module_names:
        raise SystemExit("No module candidates loaded. Pass --modules-file or a valid --db.")

    log(f"[*] probing {len(module_names)} modules")
    if args.verbose:
        log(f"[INFO] threads={args.probe_threads} timeout={args.timeout}s candidates={len(module_names)}")
    modules = enumerate_modules(
        sorted(module_names),
        base_url,
        args.timeout,
        args.user_agent,
        args.insecure,
        args.probe_threads,
        on_found=lambda result: log(f"[+] {result['name']} {result['version']}"),
        on_progress=(
            (lambda done, total: log(f"[INFO] module probes completed: {done}/{total}"))
            if args.verbose else None
        ),
        on_request=(
            (lambda name, path, status: log(f"[HTTP] {name} {path} -> {status}"))
            if args.verbose >= 2 else None
        ),
    )

    infer_core_from_modules(core, modules)
    if args.fingerprint_core:
        fingerprint_core(
            core,
            base_url,
            args.core_hash_db,
            args.timeout,
            args.user_agent,
            args.insecure,
        )
    if args.check_vulns:
        check_vulns(core, modules, args.timeout, args.user_agent, args.insecure)

    emit_results({"core": core, "modules": modules}, args)
    if args.verbose:
        log(f"[INFO] finished in {time.monotonic() - started:.1f}s; modules found={len(modules)}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="drupenum",
        description="Enumerate exposed Drupal modules.",
    )
    parser.add_argument("target")
    parser.add_argument("-o", "--output")
    parser.add_argument("--json", action="store_true", help="print/write JSON")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite module cache")
    parser.add_argument(
        "--core-hash-db",
        default=DEFAULT_CORE_HASH_DB,
        help="SQLite core hash cache",
    )
    parser.add_argument("--modules-file", help="module names, one per line")
    parser.add_argument("--check-vulns", action="store_true", help="query OSV")
    parser.add_argument("--fingerprint-core", action="store_true", help="hash static core files")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="-v: progress every 100 modules; -vv: each HTTP request and outcome",
    )
    parser.add_argument("--probe-threads", type=int, default=PROBE_THREADS)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--user-agent", default=USER_AGENT)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="colorize text output",
    )
    parser.add_argument(
        "--no-color",
        action="store_const",
        const="never",
        dest="color",
        help="disable colored text output",
    )
    return parser.parse_args(argv)


def load_candidates(args):
    modules = set()
    if args.modules_file:
        modules |= load_file_modules(args.modules_file)

    db_modules = load_db_modules(args.db)
    if db_modules:
        log(f"[*] loaded {len(db_modules)} modules from {args.db}")
        modules |= db_modules
    return modules


def emit_results(data, args):
    output = json.dumps(data, indent=2) if args.json else None
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output or json.dumps(data, indent=2))
        log(f"[+] saved: {args.output}")
    elif args.json:
        print(output)
    else:
        print_text(data["core"], data["modules"], color=args.color)


def log(message):
    print(message, file=sys.stderr)
