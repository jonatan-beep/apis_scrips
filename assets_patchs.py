"""
assets_patchs.py — Patch exposure per endpoint (OS + App patches)

3-step BE approach:
  Step 1: List all OS / App products with pending patches
  Step 2: For each OS/product -> list available patches
  Step 3: For each patch -> list affected endpoints

Output: one flat CSV row per (endpoint × patch).

State: processed hashes stored in state.json so interrupted runs resume
       from where they left off. On complete success, state is cleared so
       the next run creates a new file.
"""

import argparse
import json
import os
import time
import requests
from datetime import datetime
from _paths import result_path, write_csv_append, load_state, save_state, state_path
from _paginate import AdaptivePaginator

BASE_PATH = "vicarius-external-data-api"
SCOPE = "assets_patchs"
PAGE_SIZE = 500

VULN_CSV_FIELDS = [
    "patch_id",
    "patch_name",
    "patch_type",
    "publisher_name",
    "cve_id",
    "vulnerability_id",
    "vulnerability_summary",
    "severity",
    "cvss_score",
    "cvss_vector",
    "impact_level",
    "exploitability_level",
    "published_at",
    "modified_at",
    "cisa_action",
]

CSV_FIELDS = [
    "patch_type",
    "publisher_name",
    "os_name",
    "os_family",
    "product_name",
    "patch_id",
    "patch_name",
    "patch_description",
    "sensitivity_level_name",
    "patch_release_date",
    "external_reference_id",
    "endpoint_hash",
    "endpoint_name",
    "endpoint_score",
    "endpoint_status",
]

_STEP2_GROUP = (
    "organizationEndpointExternalReferenceExternalReferencesPatches.patchName.raw;"
    "organizationEndpointExternalReferenceExternalReferencesPatches.patchReleaseDate;"
    "organizationEndpointExternalReferenceExternalReferencesPatches.patchDescription;"
    "organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelName;"
    "organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelRank;"
    "externalReferenceId;>;"
    "organizationEndpointExternalReferenceExternalReferencesPatches.patchId;"
    "externalReferenceSourceId;endpointId"
)

_STEP3_SORT = "-endpointEndpointScores.endpointScoresScore;-endpointAlive;endpointId"
_STEP3_FIELDS = (
    "endpointId,endpointName,endpointHash,"
    "endpointEndpointScores.endpointScoresScore,"
    "endpointEndpointSubStatus.endpointSubStatusName,"
    "endpointOperatingSystem.operatingSystemName,"
    "endpointOperatingSystemFamily.operatingSystemFamilyName"
)

# Step 3 join config per patch type
_STEP3_JOIN = {
    "OS": {
        "object": "OrganizationEndpointPublisherOperatingSystems",
        "field": "publisherOperatingSystemHash",
        "ex_field": "organizationEndpointPublisherOperatingSystemsExternalReferenceSecondary.externalReferenceId",
    },
    "App": {
        "object": "OrganizationEndpointPublisherProductVersions",
        "field": "publisherProductHash",
        "ex_field": "organizationEndpointPublisherProductVersionsExternalReferenceSecondary.externalReferenceId",
    },
}


# ── Env ────────────────────────────────────────────────────────────────────────

def _load_env():
    env = {}
    env_path = os.path.join(os.getcwd(), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env.get("APIKEY"), env.get("DASHBOARD")


# ── Rate limit — 1.2s minimum per HTTP call ────────────────────────────────────

def _rate_call(fn, *args, **kwargs):
    t0 = time.monotonic()
    result = fn(*args, **kwargs)
    wait = 1.2 - (time.monotonic() - t0)
    if wait > 0:
        time.sleep(wait)
    return result


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _do_post(url, headers, params, payload, paginator=None):
    if paginator:
        resp = paginator.fetch_page(url, params, method="POST", headers=headers, size_param_name="pageSize", body=payload)
    else:
        resp = _rate_call(requests.post, url, headers=headers, params=params, json=payload, timeout=30)
        if resp.status_code == 429:
            wait = int(resp.headers.get("Retry-After", 60))
            print(f"  Rate limited, waiting {wait}s...")
            time.sleep(wait)
            return _do_post(url, headers, params, payload)
        if 500 <= resp.status_code < 600:
            print(f"  Server error {resp.status_code}, waiting 15s...")
            time.sleep(15)
            return _do_post(url, headers, params, payload)
        resp.raise_for_status()
        resp = resp.json()
    return resp


def _do_get(url, headers, params, paginator=None):
    if paginator:
        resp = paginator.fetch_page(url, params, method="GET", headers=headers, size_param_name="size")
    else:
        resp = _rate_call(requests.get, url, headers=headers, params=params, timeout=30)
        if resp.status_code == 429:
            wait = int(resp.headers.get("Retry-After", 60))
            print(f"  Rate limited, waiting {wait}s...")
            time.sleep(wait)
            return _do_get(url, headers, params)
        if 500 <= resp.status_code < 600:
            print(f"  Server error {resp.status_code}, waiting 15s...")
            time.sleep(15)
            return _do_get(url, headers, params)
        resp.raise_for_status()
        resp = resp.json()
    return resp


# ── Step 4: vulnerabilities per patch (OS only) ───────────────────────────────

_VULN_JOIN = {
    "OS": {
        "hash_field": "publisherOperatingSystemHash",
        "join_object": "OrganizationEndpointPublisherOperatingSystems",
        "join_by": "endpointExternalReferenceSecondaryHash",
        "join_foreign": "endpointExternalReferenceHash",
        "ex_field": "organizationEndpointPublisherOperatingSystemsExternalReferenceSecondary.externalReferenceId",
    },
    "App": {
        "hash_field": "publisherProductHash",
        "join_object": "OrganizationEndpointPublisherProductVersions",
        "join_by": "endpointId",
        "join_foreign": "endpointId",
        "ex_field": "organizationEndpointPublisherProductVersionsExternalReferenceSecondary.externalReferenceId",
    },
}


def _fetch_vuln_ids(base, headers, external_ref_id, type_hash, patch_type):
    """4a: locate vulnerability IDs linked to a patch via external_ref_id."""
    jc = _VULN_JOIN[patch_type]
    q = (
        f"organizationEndpointVulnerabilitiesPatch.externalReferenceId=in=({external_ref_id});"
        f"{jc['hash_field']}=in=({type_hash})"
    )
    return _do_post(
        f"{base}/aggregation/searchGroup",
        headers,
        {
            "from": "0", "size": "100",
            "objectName": "OrganizationEndpointVulnerabilities",
            "group": (
                "organizationEndpointVulnerabilitiesPatch.externalReferenceId;"
                "vulnerabilityId;"
                "organizationEndpointVulnerabilitiesVulnerability.vulnerabilityExternalReference.externalReferenceId"
            ),
            "includeOriginalDoc": "false",
            "q": q,
            "sort": "aggregationId",
            "sumLastSubAggregationBuckets": "2",
            "newParser": "true",
        },
        [{
            "searchQueryName": "patchVulnerabilities",
            "searchQueryObjectName": "OrganizationEndpointVulnerabilities",
            "searchQueryObjectJoinByFieldName": "organizationEndpointVulnerabilitiesPatch.externalReferenceId",
            "searchQueryObjectJoinByForeignFieldName": "organizationEndpointVulnerabilitiesPatch.externalReferenceId",
            "searchQueryQuery": q,
        }],
    )


def _fetch_vuln_details(base, headers, vuln_ids, type_hash, patch_id, patch_type):
    """4b: fetch full vulnerability documents for the given vuln_ids."""
    jc = _VULN_JOIN[patch_type]
    ids_str = ",".join(map(str, vuln_ids))
    return _do_post(
        f"{base}/aggregation/searchGroup",
        headers,
        {
            "from": "0", "size": "100",
            "objectName": "OrganizationEndpointVulnerabilities",
            "group": "vulnerabilityId;endpointId",
            "includeOriginalDoc": "true",
            "q": (
                f"vulnerabilityId=in=({ids_str});"
                f"{jc['hash_field']}=in=({type_hash});"
                f"organizationEndpointVulnerabilitiesPatch.patchId=in=({patch_id})"
            ),
            "sort": "aggregationId",
            "sumLastSubAggregationBuckets": "1",
        },
        [
            {
                "searchQueryName": "vulnCVEs",
                "searchQueryObjectName": jc["join_object"],
                "searchQueryObjectJoinByFieldName": jc["join_by"],
                "searchQueryObjectJoinByForeignFieldName": jc["join_foreign"],
                "searchQueryQuery": (
                    f"{jc['hash_field']}=in=({type_hash});"
                    f"{jc['ex_field']}=ex=true"
                ),
                "searchQueryQueryJoinType": "",
            },
            {
                "searchQueryName": "vulnCVEs",
                "searchQueryObjectName": "OrganizationEndpointExternalReferenceExternalReferences",
                "searchQueryObjectJoinByFieldName": "externalReferenceSourceId",
                "searchQueryObjectJoinByForeignFieldName": "organizationEndpointVulnerabilitiesPatch.externalReferenceId",
                "searchQueryQuery": "",
                "searchQueryQueryJoinType": "",
            },
        ],
    )


def _extract_vulns(resp, patch_id, patch_name, patch_type, publisher_name):
    """Parse vulnerability details response into flat rows."""
    rows = []
    if not resp or "serverResponseObject" not in resp:
        return rows
    seen = set()
    for item in resp["serverResponseObject"]:
        vuln_data = (
            item.get("aggregationModelAbs", {})
            .get("organizationEndpointVulnerabilitiesVulnerability", {})
        )
        if not vuln_data:
            continue
        vuln_id = vuln_data.get("vulnerabilityId", "")
        if not vuln_id or vuln_id in seen:
            continue
        seen.add(vuln_id)
        ext_ref = vuln_data.get("vulnerabilityExternalReference", {}) or {}
        sensitivity = vuln_data.get("vulnerabilitySensitivityLevel", {}) or {}
        rows.append({
            "patch_id": str(patch_id),
            "patch_name": patch_name or "",
            "patch_type": patch_type,
            "publisher_name": publisher_name,
            "cve_id": ext_ref.get("externalReferenceExternalId", ""),
            "vulnerability_id": str(vuln_id),
            "vulnerability_summary": vuln_data.get("vulnerabilitySummary", ""),
            "severity": sensitivity.get("sensitivityLevelName", ""),
            "cvss_score": str(vuln_data.get("vulnerabilityV3BaseScore", "")),
            "cvss_vector": vuln_data.get("vulnerabilityV3Vector", "") or "",
            "impact_level": vuln_data.get("vulnerabilityV3ImpactLevel", "") or "",
            "exploitability_level": vuln_data.get("vulnerabilityV3ExploitabilityLevel", "") or "",
            "published_at": _safe_ts_ms(vuln_data.get("vulnerabilityPublishedAt")),
            "modified_at": _safe_ts_ms(vuln_data.get("vulnerabilityModifiedAt")),
            "cisa_action": vuln_data.get("vulnerabilityCISARequiredAction", "") or "",
        })
    return rows


def _get_vulns_for_patch(base, headers, patch, patch_type, publisher_name, type_hash):
    """Fetch and return vulnerability rows for one patch (OS and App)."""
    external_ref_id = patch.get("external_reference_id")
    patch_id = patch.get("patch_id")
    if not external_ref_id or not patch_id:
        return []

    try:
        id_resp = _fetch_vuln_ids(base, headers, external_ref_id, type_hash, patch_type)
    except Exception as e:
        print(f"    [vuln] error fetching IDs for patch {patch_id}: {e}")
        return []

    vuln_ids = []
    for item in (id_resp or {}).get("serverResponseObject", []):
        for agg in item.get("aggregationAggregations", []):
            if "vulnerabilityIds" in agg.get("aggregationName", "") or agg.get("aggregationName") == "vulnerabilityId":
                vuln_ids.append(agg["aggregationId"])

    if not vuln_ids:
        return []

    try:
        det_resp = _fetch_vuln_details(base, headers, vuln_ids, type_hash, patch_id, patch_type)
    except Exception as e:
        print(f"    [vuln] error fetching details for patch {patch_id}: {e}")
        return []

    return _extract_vulns(det_resp, patch_id, patch.get("patch_name"), patch_type, publisher_name)


# ── Step 1: list OS / products with patches ────────────────────────────────────

def _fetch_os_page(base, headers, page_from):
    return _do_post(
        f"{base}/organizationPublisherOperatingSystems/search",
        headers,
        {
            "from": str(page_from), "size": str(PAGE_SIZE),
            "sort": (
                "-organizationPublisherOperatingSystemsOrganizationPublisherOperatingSystemsScores"
                ".organizationPublisherOperatingSystemsScoresScore;publisherOperatingSystemHash"
            ),
            "includeFields": (
                "publisherId,operatingSystemId,publisherOperatingSystemHash,"
                "organizationPublisherOperatingSystemsPublisher.publisherName,"
                "organizationPublisherOperatingSystemsOperatingSystem.operatingSystemName,"
                "organizationPublisherOperatingSystemsOperatingSystemFamily.operatingSystemFamilyName"
            ),
        },
        [{
            "searchQueryName": "osPatchQuery",
            "searchQueryObjectName": "OrganizationEndpointPublisherOperatingSystems",
            "searchQueryObjectJoinByFieldName": "publisherOperatingSystemHash",
            "searchQueryObjectJoinByForeignFieldName": "publisherOperatingSystemHash",
            "searchQueryQuery": (
                "publisherOperatingSystemHash=out=('_','null_null');"
                "organizationEndpointPublisherOperatingSystemsExternalReferenceSecondary"
                ".externalReferenceId=ex=\"true\""
            ),
        }],
    )


def _fetch_products_page(base, headers, page_from):
    return _do_post(
        f"{base}/organizationPublisherProducts/search",
        headers,
        {
            "from": str(page_from), "size": str(PAGE_SIZE),
            "sort": (
                "-organizationPublisherProductsOrganizationPublisherProductsScores"
                ".organizationPublisherProductsScoresScore;publisherProductHash"
            ),
            "includeFields": (
                "publisherProductHash,"
                "organizationPublisherProductsProduct.productName,"
                "organizationPublisherProductsProduct.productId,"
                "organizationPublisherProductsPublisher.publisherName,"
                "organizationPublisherProductsPublisher.publisherId"
            ),
        },
        [
            {
                "searchQueryName": "appPatch",
                "searchQueryObjectName": "OrganizationEndpointPublisherProductVersions",
                "searchQueryObjectJoinByFieldName": "publisherProductHash",
                "searchQueryObjectJoinByForeignFieldName": "publisherProductHash",
                "searchQueryQuery": (
                    "organizationEndpointPublisherProductVersionsExternalReferenceSecondary"
                    ".externalReferenceId=ex=true"
                ),
            },
            {
                "searchQueryName": "appPatch",
                "searchQueryObjectName": "OrganizationEndpointPublisherProductHashtags",
                "searchQueryObjectJoinByFieldName": "publisherProductHash",
                "searchQueryObjectJoinByForeignFieldName": "publisherProductHash",
                "searchQueryQuery": "organizationEndpointPublisherProductHashtagsHashtag.hashtagTag=in=(#has_patch)",
            },
        ],
    )


def _extract_os_info(resp):
    result = []
    for item in resp.get("serverResponseObject", []):
        pub = item.get("organizationPublisherOperatingSystemsPublisher", {}) or {}
        os_obj = item.get("organizationPublisherOperatingSystemsOperatingSystem", {}) or {}
        fam = item.get("organizationPublisherOperatingSystemsOperatingSystemFamily", {}) or {}
        result.append({
            "os_hash": item.get("publisherOperatingSystemHash"),
            "publisher_name": pub.get("publisherName", ""),
            "os_family": fam.get("operatingSystemFamilyName", ""),
            "os_name": os_obj.get("operatingSystemName", ""),
        })
    return result


def _extract_product_info(resp):
    result = []
    for item in resp.get("serverResponseObject", []):
        pub = item.get("organizationPublisherProductsPublisher", {}) or {}
        prod = item.get("organizationPublisherProductsProduct", {}) or {}
        result.append({
            "product_hash": item.get("publisherProductHash"),
            "publisher_name": pub.get("publisherName", ""),
            "product_name": prod.get("productName", ""),
        })
    return result


def _paginate_step1(fetch_fn, extract_fn, label):
    page, items = 0, []
    while True:
        resp = fetch_fn(page * PAGE_SIZE)
        batch = extract_fn(resp)
        if not batch:
            break
        items.extend(batch)
        print(f"  {label}: {len(items)} fetched")
        if len(batch) < PAGE_SIZE:
            break
        page += 1
    return items


# ── Step 2: patches for an OS / product ───────────────────────────────────────

def _fetch_patches_page(base, headers, hash_value, join_object, join_field, page_from):
    return _do_post(
        f"{base}/aggregation/searchGroup",
        headers,
        {
            "from": str(page_from), "size": str(PAGE_SIZE),
            "objectName": "OrganizationEndpointExternalReferenceExternalReferences",
            "group": _STEP2_GROUP,
            "includeOriginalDoc": "false",
            "sumLastSubAggregationBuckets": "8",
            "sort": "OrganizationEndpointExternalReferenceExternalReferences.sensitivityLevelRank",
            "newParser": "true",
        },
        [{
            "searchQueryName": "query",
            "searchQueryObjectName": join_object,
            "searchQueryObjectJoinByFieldName": "endpointExternalReferenceSecondaryHash",
            "searchQueryObjectJoinByForeignFieldName": "endpointExternalReferenceHash",
            "searchQueryQuery": f"{join_field}=in=({hash_value})",
        }],
    )


def _safe_ts_ms(val):
    if not val:
        return ""
    try:
        ts = int(val)
        dt = datetime.fromtimestamp(ts / 1000 if ts > 1e10 else float(ts))
        return "" if dt.year <= 1970 else dt.isoformat()
    except (ValueError, TypeError, OSError):
        return ""


def _extract_patches(resp):
    patches = []
    for item in resp.get("serverResponseObject", []):
        patch_name = item.get("aggregationId")
        desc = sev_name = rel_date_str = None
        entries = []

        for agg in item.get("aggregationAggregations", []):
            name = agg.get("aggregationName", "")
            if "patchDescriptions" in name:
                desc = agg.get("aggregationId")
            elif "sensitivityLevelNames" in name:
                sev_name = agg.get("aggregationId")
            elif "patchReleaseDates" in name:
                rel_date_str = _safe_ts_ms(agg.get("aggregationId"))
            elif "externalReferenceIds" in name:
                for sub in agg.get("aggregationAggregations", []):
                    if "patchIds" not in sub.get("aggregationName", ""):
                        continue
                    ext_src = None
                    for ss in sub.get("aggregationAggregations", []):
                        if "externalReferenceSourceIds" in ss.get("aggregationName", ""):
                            ext_src = ss.get("aggregationId")
                    try:
                        pid = int(sub.get("aggregationId"))
                    except (TypeError, ValueError):
                        pid = None
                    entries.append({"patch_id": pid, "ext_src": ext_src})

        base_patch = {
            "patch_name": patch_name,
            "sensitivity_level_name": sev_name,
            "patch_description": desc,
            "patch_release_date": rel_date_str or "",
        }

        if entries:
            for e in entries:
                rec = dict(base_patch)
                rec["patch_id"] = e["patch_id"]
                try:
                    rec["external_reference_id"] = int(e["ext_src"]) if e["ext_src"] else None
                except (TypeError, ValueError):
                    rec["external_reference_id"] = None
                patches.append(rec)
        else:
            base_patch["patch_id"] = None
            base_patch["external_reference_id"] = None
            patches.append(base_patch)

    return patches


# ── Step 3: endpoints for a patch ─────────────────────────────────────────────

def _fetch_endpoints_page(base, headers, patch_id, type_hash, patch_type, page_from):
    join = _STEP3_JOIN[patch_type]
    return _do_post(
        f"{base}/endpoint/search",
        headers,
        {
            "from": str(page_from), "size": str(PAGE_SIZE),
            "sort": _STEP3_SORT,
            "includeFields": _STEP3_FIELDS,
        },
        [
            {
                "searchQueryName": "missingUpdates",
                "searchQueryObjectName": "OrganizationEndpointExternalReferenceExternalReferences",
                "searchQueryObjectJoinByFieldName": "endpointExternalReferenceHash",
                "searchQueryObjectJoinByForeignFieldName": "endpointExternalReferenceSecondaryHash",
                "searchQueryQuery": (
                    f"organizationEndpointExternalReferenceExternalReferencesPatches.patchId=in=({patch_id})"
                ),
            },
            {
                "searchQueryName": "typeFilter",
                "searchQueryObjectName": join["object"],
                "searchQueryObjectJoinByFieldName": "endpointId",
                "searchQueryObjectJoinByForeignFieldName": "endpointId",
                "searchQueryQuery": (
                    f"{join['field']}=in=({type_hash});"
                    f"{join['ex_field']}=ex=true"
                ),
            },
        ],
    )


def _extract_endpoints(resp):
    result = []
    for item in resp.get("serverResponseObject", []):
        scores = item.get("endpointEndpointScores", {}) or {}
        status = item.get("endpointEndpointSubStatus", {}) or {}
        os_obj = item.get("endpointOperatingSystem", {}) or {}
        os_fam = item.get("endpointOperatingSystemFamily", {}) or {}
        os_name = os_obj.get("operatingSystemName", "")
        family = os_fam.get("operatingSystemFamilyName", "")
        if not family and os_name:
            lower = os_name.lower()
            if "windows" in lower:
                family = "Windows"
            elif "macos" in lower or "mac os" in lower:
                family = "macOS"
            elif any(x in lower for x in ["linux", "ubuntu", "debian", "centos", "rhel", "suse", "fedora"]):
                family = "Linux"
        result.append({
            "endpoint_hash": item.get("endpointHash", ""),
            "endpoint_name": item.get("endpointName", ""),
            "endpoint_score": str(scores.get("endpointScoresScore", "")),
            "endpoint_status": status.get("endpointSubStatusName", ""),
            "os_name_ep": os_name,
            "os_family_ep": family,
        })
    return result


# ── Process one OS or product entry ───────────────────────────────────────────

def _process_entry(base, headers, dashboard, run_file, vuln_run_file,
                   processed_patch_vuln_ids,
                   entry_hash, patch_type,
                   step2_join_object, step2_join_field,
                   static_fields):
    """
    Step 2: collect patches for this entry.
    Step 3: for each patch collect affected endpoints.
    Step 4: for each OS patch (deduplicated by patch_id) collect CVEs.
    Saves to CSV immediately per patch (not accumulated).
    """
    page, total_rows = 0, 0

    while True:
        resp = _fetch_patches_page(
            base, headers, entry_hash,
            step2_join_object, step2_join_field,
            page * PAGE_SIZE,
        )
        patches = _extract_patches(resp)
        if not patches:
            break

        for patch in patches:
            if not patch.get("patch_id"):
                continue

            ep_page, ep_rows = 0, []
            while True:
                ep_resp = _fetch_endpoints_page(
                    base, headers, patch["patch_id"], entry_hash, patch_type, ep_page * PAGE_SIZE
                )
                batch_eps = _extract_endpoints(ep_resp)
                if not batch_eps:
                    break
                ep_rows.extend(batch_eps)
                if len(batch_eps) < PAGE_SIZE:
                    break
                ep_page += 1

            rows = []
            for ep in ep_rows:
                rows.append({
                    "patch_type": patch_type,
                    "publisher_name": static_fields.get("publisher_name", ""),
                    "os_name": static_fields.get("os_name", "") or ep["os_name_ep"],
                    "os_family": static_fields.get("os_family", "") or ep["os_family_ep"],
                    "product_name": static_fields.get("product_name", ""),
                    "patch_id": str(patch["patch_id"]),
                    "patch_name": patch["patch_name"] or "",
                    "patch_description": patch["patch_description"] or "",
                    "sensitivity_level_name": patch["sensitivity_level_name"] or "",
                    "patch_release_date": patch["patch_release_date"] or "",
                    "external_reference_id": str(patch["external_reference_id"] or ""),
                    "endpoint_hash": ep["endpoint_hash"],
                    "endpoint_name": ep["endpoint_name"],
                    "endpoint_score": ep["endpoint_score"],
                    "endpoint_status": ep["endpoint_status"],
                })

            if rows:
                write_csv_append(dashboard, SCOPE, run_file, rows, CSV_FIELDS)
                total_rows += len(rows)
                print(f"    Patch {patch['patch_name'] or patch['patch_id']}: {len(rows)} endpoints (+{total_rows} total)")

            # Step 4: vulnerabilities (OS only, deduplicated by patch_id)
            pid = patch.get("patch_id")
            if pid and pid not in processed_patch_vuln_ids:
                processed_patch_vuln_ids.add(pid)
                vuln_rows = _get_vulns_for_patch(
                    base, headers, patch, patch_type,
                    static_fields.get("publisher_name", ""), entry_hash,
                )
                if vuln_rows:
                    write_csv_append(dashboard, SCOPE, vuln_run_file, vuln_rows, VULN_CSV_FIELDS)
                    print(f"    [vuln] {patch['patch_name'] or pid}: {len(vuln_rows)} CVEs")

        if len(patches) < PAGE_SIZE:
            break
        page += 1

    return total_rows


# ── Main collection ────────────────────────────────────────────────────────────

def collect(apikey, dashboard):
    base = f"https://{dashboard}.vicarius.cloud/{BASE_PATH}"
    headers = {"Accept": "application/json", "Vicarius-Token": apikey}
    raw_store = {"step1_os": [], "step1_products": []}

    state_file = state_path(dashboard, SCOPE)
    paginator = AdaptivePaginator(state_file)

    state = load_state(dashboard, SCOPE)
    processed_os = set(state.get("processed_os_hashes", []))
    processed_products = set(state.get("processed_product_hashes", []))
    os_phase_complete = state.get("os_phase_complete", False)
    processed_patch_vuln_ids = set(state.get("processed_patch_vuln_ids", []))

    run_file = state.get("run_file")
    if not run_file:
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        run_file = f"assets_patchs_{ts}"

    vuln_run_file = f"patches_vulnerabilities_{run_file.split('_', 2)[-1]}" if "_" in run_file else f"patches_vulnerabilities_{run_file}"

    print(f"Output: result/{dashboard}/{SCOPE}/{run_file}.csv")
    print(f"Vulns:  result/{dashboard}/{SCOPE}/{vuln_run_file}.csv")

    # ── Phase 1: OS patches ────────────────────────────────────────────────────
    if not os_phase_complete:
        print("\n=== Phase 1: OS patches ===")
        all_os = _paginate_step1(
            lambda off: _fetch_os_page(base, headers, off),
            _extract_os_info, "OS entries",
        )
        raw_store["step1_os"] = all_os
        print(f"Total OS entries: {len(all_os)}")

        for i, os_info in enumerate(all_os, 1):
            h = os_info["os_hash"]
            if h in processed_os:
                continue

            print(f"[OS {i}/{len(all_os)}] {os_info['os_name']} ({os_info['publisher_name']})")
            _process_entry(
                base, headers, dashboard, run_file, vuln_run_file,
                processed_patch_vuln_ids, h, "OS",
                "OrganizationEndpointPublisherOperatingSystems",
                "publisherOperatingSystemHash",
                {
                    "publisher_name": os_info["publisher_name"],
                    "os_name": os_info["os_name"],
                    "os_family": os_info["os_family"],
                    "product_name": "",
                },
            )

            processed_os.add(h)
            save_state(dashboard, SCOPE, {
                "run_file": run_file,
                "os_phase_complete": False,
                "processed_os_hashes": list(processed_os),
                "processed_product_hashes": list(processed_products),
                "processed_patch_vuln_ids": list(processed_patch_vuln_ids),
            })

        os_phase_complete = True
        save_state(dashboard, SCOPE, {
            "run_file": run_file,
            "os_phase_complete": True,
            "processed_os_hashes": list(processed_os),
            "processed_product_hashes": list(processed_products),
            "processed_patch_vuln_ids": list(processed_patch_vuln_ids),
        })
        print(f"OS phase complete ({len(processed_os)} OS processed).")

    # ── Phase 2: App patches ───────────────────────────────────────────────────
    print("\n=== Phase 2: App patches ===")
    all_products = _paginate_step1(
        lambda off: _fetch_products_page(base, headers, off),
        _extract_product_info, "Products",
    )
    raw_store["step1_products"] = all_products
    print(f"Total products: {len(all_products)}")

    for i, prod in enumerate(all_products, 1):
        h = prod["product_hash"]
        if h in processed_products:
            continue

        print(f"[App {i}/{len(all_products)}] {prod['product_name']} ({prod['publisher_name']})")
        _process_entry(
            base, headers, dashboard, run_file, vuln_run_file,
            processed_patch_vuln_ids, h, "App",
            "OrganizationEndpointPublisherProductVersions",
            "publisherProductHash",
            {
                "publisher_name": prod["publisher_name"],
                "os_name": "",
                "os_family": "",
                "product_name": prod["product_name"],
            },
        )

        processed_products.add(h)
        save_state(dashboard, SCOPE, {
            "run_file": run_file,
            "os_phase_complete": True,
            "processed_os_hashes": list(processed_os),
            "processed_product_hashes": list(processed_products),
            "processed_patch_vuln_ids": list(processed_patch_vuln_ids),
        })

    print(f"App phase complete ({len(processed_products)} products processed).")

    # ── Clear state on complete success — next run creates new file ────────────
    save_state(dashboard, SCOPE, {
        "run_file": None,
        "os_phase_complete": False,
        "processed_os_hashes": [],
        "processed_product_hashes": [],
        "processed_patch_vuln_ids": [],
    })
    print("State cleared — next run will create a new CSV file.")

    paginator.finalize()
    return run_file, raw_store


# ── Save raw ───────────────────────────────────────────────────────────────────

def save_raw(dashboard, raw_store):
    for key, data in raw_store.items():
        if not data:
            continue
        path = result_path(dashboard, SCOPE, key, "json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"  Saved → {path}")


# ── Public function ────────────────────────────────────────────────────────────

def get_assets_patchs(apikey, dashboard):
    """Public function. Returns (run_file, raw_store)."""
    return collect(apikey, dashboard)


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    env_key, env_dashboard = _load_env()
    parser = argparse.ArgumentParser(description="Fetch patch exposure per endpoint (OS + App)")
    parser.add_argument("-k", "--api-key", default=env_key, required=not env_key)
    parser.add_argument("-d", "--dashboard", default=env_dashboard, required=not env_dashboard)
    parser.add_argument("--reset-state", action="store_true", help="Ignore saved state and start fresh")
    parser.add_argument("--raw", action="store_true", help="Save raw JSON responses")
    args = parser.parse_args()

    if not args.api_key or not args.dashboard:
        parser.error("Provide -k and -d, or place a .env file with APIKEY and DASHBOARD.")

    if args.reset_state:
        save_state(args.dashboard, SCOPE, {
            "run_file": None,
            "os_phase_complete": False,
            "processed_os_hashes": [],
            "processed_product_hashes": [],
        })
        print("State reset — next run will create a new CSV file.")

    run_file, raw_store = collect(args.api_key, args.dashboard)
    print(f"\nDone. CSV: result/{args.dashboard}/{SCOPE}/{run_file}.csv")

    if args.raw:
        save_raw(args.dashboard, raw_store)
