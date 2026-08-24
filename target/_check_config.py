# SPDX-License-Identifier: Apache-2.0
# K9x Satan
"""
K9x Satan — config-shape adapter for framework OOB checks.

The framework's BaseVulnerabilityCheck subclasses (k9_aif_abb) read their
settings as a flat, check-scoped dict off self.config (e.g.
self.config.get("approved_tools")) — the same convention ShieldGovernance's
check_config threading uses. Satan's own config.yaml keeps these same
settings under a top-level `security:` block (approved_tools,
max_requests_per_window, memory_ttl, block_on_output_markup, ...), plus a
separate top-level `cache:` block that MemoryPoisoningCheck/
RequestFrequencyCheck forward to CacheFactory.

This module builds the flat dict those checks expect from Satan's config
shape, in one place, so Router and Orchestrator don't each re-derive it.
"""

import os
import sys
from typing import Any, Dict

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def security_check_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten Satan's config.yaml security:/cache: blocks for a framework OOB check."""
    return {
        **config.get("security", {}),
        "cache": config.get("cache", {}),
    }
