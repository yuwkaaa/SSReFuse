"""On-disk cache for model responses.

Two reasons, both about the paper rather than about the bill. A cached run is
reproducible: re-running the evaluation does not quietly produce different
numbers because the model sampled differently. And the cache key includes the
model, the temperature and the exact prompt, so a changed prompt cannot be
scored against answers to the old one.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ssrefuse.corpus import REPO_ROOT

CACHE_DIR = REPO_ROOT / ".cache" / "llm"


def cache_key(provider: str, model: str, prompt: str, temperature: float,
              system: str = "") -> str:
    payload = json.dumps({"provider": provider, "model": model, "system": system,
                          "prompt": prompt, "temperature": temperature},
                         sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class ResponseCache:
    def __init__(self, directory: Path | str = CACHE_DIR, enabled: bool = True):
        self.directory = Path(directory)
        self.enabled = enabled
        self.hits = 0
        self.misses = 0
        if self.enabled:
            self.directory.mkdir(parents=True, exist_ok=True)

    def get(self, key: str) -> dict | None:
        if not self.enabled:
            return None
        path = self.directory / f"{key}.json"
        if path.exists():
            self.hits += 1
            return json.loads(path.read_text())
        self.misses += 1
        return None

    def put(self, key: str, value: dict) -> None:
        if not self.enabled:
            return
        (self.directory / f"{key}.json").write_text(json.dumps(value, indent=2))

    def stats(self) -> dict[str, int]:
        return {"hits": self.hits, "misses": self.misses}
