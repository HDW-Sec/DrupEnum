"""OSV vulnerability lookup."""

from .http import make_session

OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://osv.dev/vulnerability/"
OSV_BATCH_SIZE = 1000


def check_vulns(core, modules, timeout, user_agent, insecure=False):
    exact_queries = []
    if core["version"] != "unknown":
        query = _package_query("drupal/core")
        query["version"] = core["version"]
        exact_queries.append((query, core))

    package_queries = []
    for module in modules:
        package = f"drupal/{module['name']}"
        package_queries.append((_package_query(package), module))
        if module["version"] != "unknown":
            query = _package_query(package)
            query["version"] = module["version"]
            exact_queries.append((query, module))

    if not exact_queries and not package_queries:
        return

    session = make_session(user_agent, insecure)
    try:
        exact_results = _query_batch(exact_queries, timeout, session)
        package_results = _query_batch(package_queries, timeout, session)
    finally:
        session.close()

    for (_query, item), result in zip(exact_queries, exact_results):
        item["vulns"] = _normalize_vulns(result)
    for (_query, item), result in zip(package_queries, package_results):
        item["package_vulns"] = _normalize_vulns(result)


def vulnerability_url(vuln_id):
    return f"{OSV_VULN_URL}{vuln_id}"


def _package_query(package):
    return {"package": {"ecosystem": "Packagist", "name": package}}


def _normalize_vulns(result):
    seen = set()
    vulns = []
    for vuln in result.get("vulns", []):
        vuln_id = vuln.get("id")
        if not vuln_id or vuln_id in seen:
            continue
        seen.add(vuln_id)
        vulns.append(
            {
                "id": vuln_id,
                "summary": vuln.get("summary", ""),
                "modified": vuln.get("modified", ""),
                "url": vulnerability_url(vuln_id),
            }
        )
    return vulns


def _query_batch(query_items, timeout, session):
    if not query_items:
        return []

    results = []
    for batch in _chunks(query_items, OSV_BATCH_SIZE):
        payload = {"queries": [query for query, _item in batch]}
        response = session.post(OSV_URL, json=payload, timeout=timeout)
        response.raise_for_status()
        results.extend(response.json().get("results", []))
    return results


def _chunks(items, size):
    for index in range(0, len(items), size):
        yield items[index:index + size]
