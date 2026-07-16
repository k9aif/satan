"""
K9x Satan — process-level singleton cache for session-aware checks.

CacheFactory.create() (k9_aif_abb) is a plain factory — it constructs a brand
new adapter instance on every call, never memoizes. DocumentRouter is rebuilt
fresh on every request (target/pipeline.py constructs a new one per
run_pipeline() call), so MemoryPoisoningCheck and RequestFrequencyCheck are
also reconstructed fresh each time. If each of them called
CacheFactory.create() directly in __init__, each request would get its own
empty in-memory store — no state would ever survive between requests, and
both checks would be permanently blind to anything that requires comparing
this request against a previous one.

This module holds the one shared instance both checks read from — the
in-process equivalent of what a real Redis backend gives you for free across
processes. If cache.provider: redis is configured, this singleton just means
one client is reused instead of reconnecting per request; the correctness fix
matters specifically for the in_memory default.
"""

import os
import sys
from typing import Any, Dict, Optional

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_cache = None


def get_shared_cache(config: Optional[Dict[str, Any]] = None):
    global _cache
    if _cache is None:
        from k9_aif_abb.k9_factories.cache_factory import CacheFactory
        _cache = CacheFactory.create(config or {})
    return _cache
