"""Small, dependency-free client for FIRST's public EPSS API with local caching."""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .models import Finding

EPSS_API = "https://api.first.org/data/v1/epss?cve="


class EpssClient:
    def __init__(self, cache_path: Path, timeout_seconds: float = 8.0) -> None:
        self.cache_path = cache_path
        self.timeout_seconds = timeout_seconds
        self.cache = self._read_cache()

    def _read_cache(self) -> dict[str, dict[str, float]]:
        if not self.cache_path.exists():
            return {}
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self.cache, indent=2, sort_keys=True), encoding="utf-8")

    def lookup(self, cve: str) -> tuple[float | None, float | None]:
        key = cve.upper()
        cached = self.cache.get(key)
        if cached:
            return cached.get("epss"), cached.get("percentile")
        request = Request(f"{EPSS_API}{quote(key)}", headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # nosec B310 - fixed HTTPS API
                payload = json.loads(response.read().decode("utf-8"))
        except (URLError, TimeoutError, json.JSONDecodeError, OSError):
            return None, None
        rows = payload.get("data", []) if isinstance(payload, dict) else []
        if not rows or not isinstance(rows[0], dict):
            return None, None
        try:
            epss = float(rows[0]["epss"])
            percentile = float(rows[0]["percentile"])
        except (KeyError, TypeError, ValueError):
            return None, None
        self.cache[key] = {"epss": epss, "percentile": percentile, "fetched_at": time.time()}
        self._write_cache()
        return epss, percentile

    def enrich(self, findings: list[Finding]) -> None:
        """Attach the highest available CVE EPSS score to each finding."""
        for finding in findings:
            candidates = [self.lookup(cve) for cve in finding.cves]
            available = [(epss, percentile) for epss, percentile in candidates if epss is not None]
            if available:
                finding.epss, finding.epss_percentile = max(available, key=lambda item: item[0] or 0.0)

