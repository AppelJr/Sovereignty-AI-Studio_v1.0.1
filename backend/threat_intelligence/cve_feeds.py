"""Offline-first seven-feed CVE normalizers and EPSS enrichment.

Fixture mode is the default. These adapters are pure functions: they never
perform network I/O. Live retrieval requires an explicit caller-supplied
fetcher and FeedConfig(mode="live", allow_network=True).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Sequence
import re

CVE_RE = re.compile(r"CVE-\\d{4}-\\d{4,}", re.I)
Fetcher = Callable[[str, str, Mapping[str, str] | None, Mapping[str, Any] | None], Any]


class NetworkDisabledError(RuntimeError):
    """Live retrieval was requested without explicit network approval."""


@dataclass(frozen=True)
class FeedConfig:
    mode: str = "fixture"
    allow_network: bool = False

    def __post_init__(self) -> None:
        if self.mode not in {"fixture", "live"}:
            raise ValueError("mode must be fixture or live")
        if self.mode == "live" and not self.allow_network:
            raise NetworkDisabledError("live mode requires allow_network=True")


def _items(value: Any, key: str | None = None) -> list[Mapping[str, Any]]:
    if key and isinstance(value, Mapping):
        value = value.get(key, [])
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [v for v in value if isinstance(v, Mapping)]
    return []


def _path(value: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _float(value: Any, maximum: float = 10.0) -> float | None:
    try:
        number = float(value)
        return number if 0 <= number <= maximum else None
    except (TypeError, ValueError):
        return None


def _names(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, Mapping):
        if isinstance(value.get("name"), str):
            return _names(value["name"])
        return [s for v in value.values() for s in _names(v)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [s for v in value for s in _names(v)]
    return []


def _record(source: str, ident: Any, cve: Any, description: Any, raw: Any,
            *, date: Any = None, updated: Any = None, score: Any = None,
            vendor: Any = None, product: Any = None, url: Any = None,
            exploited: bool = False) -> dict[str, Any]:
    match = CVE_RE.search(str(cve or ""))
    normalized_cve = match.group(0).upper() if match else None
    return {
        "ID": str(ident or normalized_cve or ""),
        "Source": source,
        "url": url or (f"https://www.cve.org/CVERecord?id={normalized_cve}" if normalized_cve else None),
        "CVE": normalized_cve,
        "Description": description,
        "Relevance": None,
        "DateAdded": date,
        "Updated": updated,
        "BaseScore": _float(score),
        "Vendor": ", ".join(_names(vendor)) or "n/a",
        "Product": ", ".join(_names(product)) or "n/a",
        "KnownExploited": bool(exploited),
        "RawData": raw,
        "EPSS": None,
        "EpssUnit": None,
        "EpssSource": None,
        "EpssPercentile": None,
        "ExploitabilityScore": None,
        "poc": None,
    }


def adapt_euvd(data: Any) -> list[dict[str, Any]]:
    out = []
    for item in _items(data, "items"):
        aliases = item.get("aliases") or ""
        match = CVE_RE.search("\\n".join(aliases) if isinstance(aliases, list) else str(aliases))
        ident = item.get("id")
        row = _record("EUVD", ident, match.group(0) if match else None,
                      item.get("description"), item,
                      date=item.get("datePublished"), updated=item.get("dateUpdated"),
                      score=item.get("baseScore"),
                      vendor=_path(item, "enisaIdVendor", "Vendor"),
                      product=_path(item, "enisaIdProduct", "product"),
                      url=f"https://euvd.enisa.europa.eu/enisa/{ident}" if ident else None,
                      exploited=bool(item.get("exploitedSince")))
        if item.get("epss") not in (None, ""):
            try:
                row.update(EPSS=round(float(item["epss"]), 2), EpssUnit="%", EpssSource="EUVD")
            except (TypeError, ValueError):
                pass
        out.append(row)
    return out


def adapt_nvd(data: Any) -> list[dict[str, Any]]:
    out = []
    for wrapper in _items(data, "vulnerabilities"):
        cve = wrapper.get("cve", wrapper)
        ident = cve.get("id")
        if not isinstance(ident, str) or not CVE_RE.fullmatch(ident):
            continue
        desc = next((d.get("value") for d in _items(cve, "descriptions") if d.get("lang") == "en"), "n/a")
        metrics = cve.get("metrics") or {}
        score = exploit = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = _items(metrics, key)
            if entries:
                score = _path(entries[0], "cvssData", "baseScore")
                exploit = entries[0].get("exploitabilityScore")
                if score is not None:
                    break
        vendors: list[str] = []
        products: list[str] = []
        def walk(nodes: Any) -> None:
            for node in _items(nodes):
                for match in _items(node, "cpeMatch"):
                    parts = str(match.get("criteria") or match.get("cpe23Uri") or "").split(":")
                    if len(parts) >= 5:
                        if parts[3] not in {"", "*", "-"}: vendors.append(parts[3])
                        if parts[4] not in {"", "*", "-"}: products.append(parts[4])
                walk(node.get("nodes"))
                walk(node.get("children"))
        walk(cve.get("configurations"))
        row = _record("NVD", ident, ident, desc, cve, date=cve.get("published"),
                      updated=cve.get("lastModified"), score=score, vendor=list(dict.fromkeys(vendors)),
                      product=list(dict.fromkeys(products)), url=f"https://nvd.nist.gov/vuln/detail/{ident}")
        row["ExploitabilityScore"] = _float(exploit, 100.0)
        out.append(row)
    return out


def adapt_kev(data: Any, enrichment: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    entries = _items(data, "vulnerabilities") or _items(data, "data") or _items(data)
    extras = {str(k).upper(): v for k, v in (enrichment or {}).items()}
    out = []
    for item in entries:
        cve = item.get("cveID")
        if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
            continue
        extra = extras.get(cve.upper(), {})
        nvd = _items(extra, "nvdData")
        nvd0 = nvd[0] if nvd else {}
        date = str(item.get("dateAdded") or "").split("T")[0] or None
        row = _record("KEV", cve, cve,
                      " - ".join(x for x in (str(item.get("vulnerabilityName") or ""),
                                              str(item.get("shortDescription") or "")) if x),
                      item, date=date, score=nvd0.get("baseScore"),
                      vendor=item.get("vendorProject"), product=item.get("product"), exploited=True)
        row.update(Note=f"added to KEV on {date}", KnownRansomware=item.get("knownRansomwareCampaignUse") == "Known",
                   KevDueDate=str(item.get("dueDate") or "").split("T")[0] or None,
                   KevRequiredAction=item.get("requiredAction"),
                   ExploitabilityScore=_float(nvd0.get("exploitabilityScore"), 100.0),
                   poc=1 if _items(extra, "githubPocs") else 0)
        out.append(row)
    return out


def adapt_redhat(data: Any, *, now: datetime | None = None, lookback_days: int | None = 3) -> list[dict[str, Any]]:
    if lookback_days is not None and lookback_days < 0:
        raise ValueError("lookback_days cannot be negative")
    now = now or datetime.now(timezone.utc)
    out = []
    for item in (_items(data, "items") or _items(data)):
        published = item.get("public_date")
        try:
            date = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            if lookback_days is not None and (now - date.astimezone(timezone.utc)).total_seconds() > lookback_days * 86400:
                continue
        except (TypeError, ValueError):
            continue
        cve = item.get("CVE") or item.get("bugzilla")
        description = str(item.get("bugzilla_description") or "")
        vendor = product = "n/a"
        if ":" in description:
            first, rest = description.split(":", 1)
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", first.strip()):
                vendor = product = first.strip()
                description = rest.strip()
        row = _record("RedHat Security", cve, cve, description,
                      {"redhatFixedPackages": _names(item.get("affected_packages"))},
                      date=published, score=item.get("cvss3_score"), vendor=vendor,
                      product=product, url=item.get("resource_url"))
        row["CWE"] = item.get("CWE")
        out.append(row)
    return out


def _metrics_score(metrics: Any) -> float | None:
    for metric in _items(metrics):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0", "cvss_v3"):
            value = metric.get(key)
            score = _float(value.get("baseScore")) if isinstance(value, Mapping) else None
            if score is not None:
                return score
    return None


def adapt_circl(data: Any) -> list[dict[str, Any]]:
    out = []
    for doc in _items(data):
        ident = cve = desc = url = vendor = None
        products: list[str] = []
        score = date = updated = None
        exploited = False
        meta = doc.get("cveMetadata")
        if isinstance(meta, Mapping):
            cna = _path(doc, "containers", "cna") or {}
            ident = meta.get("cveId") or meta.get("vulnId")
            cve = meta.get("cveId")
            descriptions = _items(cna, "descriptions")
            desc = cna.get("title") or next((d.get("value") for d in descriptions if str(d.get("lang", "")).startswith("en")), None)
            refs = _items(cna, "references")
            url = next((r.get("url") for r in refs if str(r.get("url", "")).startswith("http")), None)
            affected = _items(cna, "affected")
            vendor = next((a.get("vendor") for a in affected if a.get("vendor")), _path(cna, "providerMetadata", "shortName"))
            products = [str(a.get("product") or a.get("packageName")) for a in affected if a.get("product") or a.get("packageName")]
            score = _metrics_score(cna.get("metrics"))
            for adp in _items(_path(doc, "containers", "adp")):
                score = score if score is not None else _metrics_score(adp.get("metrics"))
                exploited = exploited or any(_path(m, "other", "type") == "kev" for m in _items(adp, "metrics"))
            date, updated = meta.get("datePublished") or meta.get("dateUpdated"), meta.get("dateUpdated")
        elif isinstance(_path(doc, "document", "tracking"), Mapping):
            tracking = _path(doc, "document", "tracking")
            ident, desc = tracking.get("id"), _path(doc, "document", "title")
            vendor = _path(doc, "document", "publisher", "name")
            vulns = _items(doc, "vulnerabilities")
            cve = next((v.get("cve") for v in vulns if v.get("cve")), None)
            refs = _items(_path(doc, "document", "references"))
            url = next((r.get("url") for r in refs if r.get("category") == "self"), None)
            scores = [_float(_path(s, "cvss_v3", "baseScore")) for v in vulns for s in _items(v, "scores")]
            score = max((s for s in scores if s is not None), default=None)
            date, updated = tracking.get("initial_release_date"), tracking.get("current_release_date")
        elif isinstance(doc.get("id"), str):
            ident = doc["id"]
            aliases = _names(doc.get("aliases"))
            cve = ident if CVE_RE.fullmatch(ident) else next((a for a in aliases if CVE_RE.fullmatch(a)), None)
            desc = doc.get("summary") or doc.get("details")
            refs = _items(doc, "references")
            url = next((r.get("url") for r in refs if str(r.get("url", "")).startswith("http")), None)
            affected = _items(doc, "affected")
            products = [str(_path(a, "package", "name")) for a in affected if _path(a, "package", "name")]
            vendor = next((_path(a, "package", "ecosystem") for a in affected if _path(a, "package", "ecosystem")), None)
            scores = [_float(s.get("score")) for s in _items(doc, "severity")]
            score = max((s for s in scores if s is not None), default=None)
            date, updated = doc.get("published"), doc.get("modified")
        else:
            continue
        out.append(_record("CIRCL", ident, cve, desc, doc, date=date, updated=updated,
                           score=score, vendor=vendor, product=products, url=url, exploited=exploited))
    return out


def adapt_osv(data: Any) -> list[dict[str, Any]]:
    out = []
    for item in (_items(data, "vulns") or _items(data)):
        ident = item.get("id")
        if not isinstance(ident, str):
            continue
        aliases = _names(item.get("aliases"))
        cve = ident if CVE_RE.fullmatch(ident) else next((a for a in aliases if CVE_RE.fullmatch(a)), None)
        affected = _items(item, "affected")
        products = [_path(a, "package", "name") for a in affected if _path(a, "package", "name")]
        vendor = next((_path(a, "package", "ecosystem") for a in affected if _path(a, "package", "ecosystem")), None)
        refs = _items(item, "references")
        url = next((r.get("url") for r in refs if str(r.get("url", "")).startswith("http")), None)
        scores = [_float(s.get("score")) for s in _items(item, "severity")]
        row = _record("OSV", ident, cve, item.get("summary") or item.get("details"), item,
                      date=item.get("published"), updated=item.get("modified"),
                      score=max((s for s in scores if s is not None), default=None),
                      vendor=vendor, product=products, url=url or f"https://osv.dev/vulnerability/{ident}")
        row["Aliases"] = aliases
        out.append(row)
    return out


def adapt_ghsa(data: Any) -> list[dict[str, Any]]:
    out = []
    for item in _items(data):
        if item.get("withdrawn_at"):
            continue
        ident = item.get("ghsa_id")
        vulns = _items(item, "vulnerabilities")
        cve = item.get("cve_id") or next((v.get("cve_id") for v in vulns if v.get("cve_id")), None)
        refs = _items(item, "references")
        url = next((r.get("url") for r in refs if r.get("url")), None)
        row = _record("GHSA", ident, cve, item.get("summary") or item.get("description"), item,
                      date=item.get("published_at"), updated=item.get("updated_at"),
                      score=_path(item, "cvss", "score"),
                      product=[_path(v, "package", "name") for v in vulns if _path(v, "package", "name")],
                      url=url or (f"https://github.com/advisories/{ident}" if ident else None))
        row["GHSA"] = ident
        row["Vulnerabilities"] = vulns
        out.append(row)
    return out


ADAPTERS = {
    "EUVD": adapt_euvd, "NVD": adapt_nvd, "KEV": adapt_kev,
    "CIRCL": adapt_circl, "RedHat": adapt_redhat, "OSV": adapt_osv,
    "GHSA": adapt_ghsa,
}


def enrich_epss(records: Iterable[dict[str, Any]], data: Any) -> None:
    """FIRST EPSS fractions become percentages; EUVD percent is fallback."""
    values: dict[str, tuple[float, float | None]] = {}
    for entry in _items(data, "data") or _items(data):
        cve = entry.get("cve")
        if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
            continue
        try:
            epss = float(entry["epss"])
            pct = float(entry["percentile"]) if entry.get("percentile") is not None else None
        except (KeyError, TypeError, ValueError):
            continue
        if 0 <= epss <= 1 and (pct is None or 0 <= pct <= 1):
            values[cve.upper()] = (round(epss * 100, 2), round(pct * 100, 2) if pct is not None else None)
    for row in records:
        key = str(row.get("CVE") or "").upper()
        if key in values:
            value, percentile = values[key]
            row.update(EPSS=value, EpssUnit="%", EpssSource="FIRST", EpssPercentile=percentile)
        elif row.get("EPSS") is not None:
            row.setdefault("EpssUnit", "%")
            row.setdefault("EpssSource", row.get("Source"))
            row.setdefault("EpssPercentile", None)
        else:
            row.update(EPSS=None, EpssUnit=None, EpssSource=None, EpssPercentile=None)


def fetch_feed(config: FeedConfig, fetcher: Fetcher | None, method: str, url: str,
               *, headers: Mapping[str, str] | None = None,
               body: Mapping[str, Any] | None = None) -> Any:
    """The only network boundary; no default HTTP client or implicit fetch."""
    if config.mode != "live" or not config.allow_network:
        raise NetworkDisabledError("fixture mode: network access is disabled")
    if fetcher is None:
        raise NetworkDisabledError("live mode requires an injected fetcher")
    return fetcher(method, url, headers, body)


def run_fixture_pipeline(fixtures: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize fixtures only and return merged CVEs as a top-level array."""
    rows: list[dict[str, Any]] = []
    for name, adapter in ADAPTERS.items():
        if name not in fixtures:
            continue
        payload = fixtures[name]
        if name == "KEV" and isinstance(payload, Mapping):
            rows.extend(adapter(payload.get("data", payload), payload.get("enrichment")))
        elif name == "RedHat":
            rows.extend(adapter(payload, lookback_days=None))
        else:
            rows.extend(adapter(payload))
    if fixtures.get("EPSS") is not None:
        enrich_epss(rows, fixtures["EPSS"])
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("CVE") or row.get("ID") or "").upper()
        if not key:
            continue
        if key not in merged:
            merged[key] = {**row, "SourceObservations": [dict(row)]}
            continue
        current = merged[key]
        current["SourceObservations"].append(dict(row))
        current["KnownExploited"] = bool(current.get("KnownExploited") or row.get("KnownExploited"))
        for field in ("Description", "DateAdded", "Updated", "BaseScore", "Vendor", "Product", "url"):
            if current.get(field) in (None, "", "n/a") and row.get(field) not in (None, "", "n/a"):
                current[field] = row[field]
    return sorted(merged.values(), key=lambda r: r.get("CVE") or r.get("ID") or "")


def legacy_json_shape(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the legacy top-level JSON array contract; do not add an envelope."""
    return [dict(record) for record in records]
