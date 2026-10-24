# SPDX-License-Identifier: Apache-2.0
# K9x Satan
"""
TargetProfile — how Satan talks to a running application over HTTP.

The attacking side (attacks/, runner/, report/) knows only a profile: where to
send each attack payload, how to shape the request, and how to read the answer.
Satan's own sample application is just the default profile
(targets/satan_sample.yaml) going through this same code, so there is no
special path for it. Design: docs/target-profiles.md.

Outcome rules are one-sided on purpose. Every Satan payload is malicious, so:
  a blocked_when rule matches          → "blocked"
  2xx and no rule matches              → "completed" (reached output: a finding)
  anything else (401, 404, 5xx, ...)   → TargetInconclusive (FLAGGED upstream)
Satan never reports BLOCKED because it could not tell.
"""

import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional

import requests
import yaml

SAMPLE_PROFILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "targets", "satan_sample.yaml")

_ENV_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")
_ONLY_PLACEHOLDER = re.compile(r"^\{\{\s*([a-z_]+)\s*\}\}$")

# placeholder → attack payload key
_PAYLOAD_FIELDS = {
    "attack_text":    "document_text",
    "filename":       "filename",
    "session_id":     "session_id",
    "tool_name":      "tool_name",
    "tool_arguments": "tool_arguments",
    "command":        "command",
    "correlation_id": "correlation_id",
}

_MAX_BODY_CHARS = 2000

# Structured fields some attacks add; a control that inspects them is only
# tested if the profile actually sends them.
_STRUCTURED_FIELDS = ("tool_name", "tool_arguments", "command")


class TargetProfileError(ValueError):
    """The profile itself is wrong: missing fields, unauthorized, unset env var."""


class TargetInconclusive(Exception):
    """The target answered, but not in a way that says blocked or not (auth, path, 5xx)."""


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def sub(m):
            name = m.group(1)
            if name not in os.environ:
                raise TargetProfileError(f"environment variable {name} is not set (used in the target profile)")
            return os.environ[name]
        return _ENV_VAR.sub(sub, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _json_path(data: Any, path: str) -> Any:
    """Dotted path into parsed JSON ("detail.check", "results.0.blocked"); None if absent."""
    cur = data
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
        if cur is None:
            return None
    return cur


class TargetProfile:
    """One running application Satan is authorized to attack."""

    def __init__(self, data: Dict[str, Any], source: str = "<dict>"):
        if not isinstance(data, dict):
            raise TargetProfileError(f"{source}: a target profile must be a mapping")
        if data.get("authorized") is not True:
            raise TargetProfileError(
                f"{source}: set 'authorized: true' to confirm you own this system or have written "
                f"permission to test it. Satan fires real attacks.")
        self.source = source
        self.name = str(data.get("name") or source)
        self.base_url = str(data.get("base_url") or "").rstrip("/")
        if not self.base_url:
            raise TargetProfileError(f"{source}: base_url is required")
        self.timeout = float(data.get("timeout", 30))

        req = data.get("request") or {}
        self.method = str(req.get("method", "POST")).upper()
        self.path = str(req.get("path") or "")
        if not self.path.startswith("/"):
            raise TargetProfileError(f"{source}: request.path is required and must start with '/'")
        self.format = str(req.get("format", "json")).lower()
        if self.format not in ("json", "multipart"):
            raise TargetProfileError(f"{source}: request.format must be json or multipart")
        self.body = req.get("body", "{{payload}}")
        self.file_field = req.get("file_field")
        if self.format == "multipart" and not self.file_field:
            raise TargetProfileError(f"{source}: request.file_field is required with format: multipart")
        self._headers = data.get("headers") or {}

        resp = data.get("response") or {}
        self.blocked_when: List[Dict[str, Any]] = list(resp.get("blocked_when") or [])
        if not self.blocked_when:
            raise TargetProfileError(
                f"{source}: response.blocked_when needs at least one rule; without one every "
                f"attack would be reported as a finding")
        self.depth_rule = resp.get("depth") or {}
        self.blocked_by_rule = resp.get("blocked_by") or {}
        self.supports_governance_override = bool(resp.get("supports_governance_override", False))

        # One session per run, for attacks that don't bring their own.
        self._run_session = f"satan-{uuid.uuid4().hex[:8]}"

    # ---------------------------------------------------------------- loading

    @classmethod
    def load(cls, path: str, base_url: Optional[str] = None) -> "TargetProfile":
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if base_url:
            data["base_url"] = base_url
        return cls(data, source=path)

    @classmethod
    def sample(cls, base_url: Optional[str] = None) -> "TargetProfile":
        """Satan's own sample application (the default target)."""
        return cls.load(SAMPLE_PROFILE, base_url=base_url)

    def check(self) -> None:
        """Fail before the first attack if a header's ${VAR} is unset."""
        _expand_env(self._headers)

    def undelivered(self, payload: Dict[str, Any]) -> List[str]:
        """Structured payload fields this profile's request never sends to the target."""
        used = set(_PLACEHOLDER.findall(json.dumps(self.body)))
        if "payload" in used:  # the whole payload goes through
            return []
        return [f for f in _STRUCTURED_FIELDS if payload.get(f) not in (None, "", {}) and f not in used]

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.path}"

    # -------------------------------------------------------------- rendering

    def _values(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        values = {ph: payload.get(key) for ph, key in _PAYLOAD_FIELDS.items()}
        values["session_id"] = values["session_id"] or self._run_session
        values["filename"] = values["filename"] or "attack.txt"
        values["payload"] = payload
        return values

    def _render(self, template: Any, values: Dict[str, Any]) -> Any:
        if isinstance(template, dict):
            return {k: self._render(v, values) for k, v in template.items()}
        if isinstance(template, list):
            return [self._render(v, values) for v in template]
        if not isinstance(template, str):
            return template
        whole = _ONLY_PLACEHOLDER.match(template.strip())
        if whole:  # keep the value's type: a dict stays a dict
            v = values.get(whole.group(1))
            return "" if v is None else v
        def sub(m):
            v = values.get(m.group(1))
            if v is None:
                return ""
            return v if isinstance(v, str) else json.dumps(v)
        return _PLACEHOLDER.sub(sub, template)

    # ---------------------------------------------------------------- sending

    def send(self, payload: Dict[str, Any], governance_mode: Optional[str] = None) -> requests.Response:
        payload = dict(payload)
        if governance_mode and self.supports_governance_override:
            payload["_governance_override"] = governance_mode
        values = self._values(payload)
        headers = _expand_env(self._headers)
        body = self._render(self.body, values)

        if self.format == "json":
            return requests.request(self.method, self.url, json=body, headers=headers, timeout=self.timeout)

        fields = body if isinstance(body, dict) else {}
        data = {k: (v if isinstance(v, str) else json.dumps(v)) for k, v in fields.items()}
        files = {self.file_field: (values["filename"], (values["attack_text"] or "").encode("utf-8"),
                                   "text/plain")}
        return requests.request(self.method, self.url, data=data, files=files, headers=headers,
                                timeout=self.timeout)

    # ------------------------------------------------------------- answering

    def _matches(self, rule: Dict[str, Any], resp: requests.Response, body: Any) -> bool:
        if "status_code" in rule:
            codes = rule["status_code"]
            codes = codes if isinstance(codes, list) else [codes]
            return resp.status_code in [int(c) for c in codes]
        if "json" in rule:
            spec = rule["json"] or {}
            value = _json_path(body, spec.get("path", ""))
            if "equals" in spec:
                return value == spec["equals"]
            if "in" in spec:
                return value in (spec["in"] or [])
            return value is not None
        if "header" in rule:
            spec = rule["header"] or {}
            value = resp.headers.get(spec.get("name", ""))
            if "equals" in spec:
                return value == spec["equals"]
            return value is not None
        if "body_contains" in rule:
            needles = rule["body_contains"]
            needles = needles if isinstance(needles, list) else [needles]
            text = resp.text.lower()
            return any(str(n).lower() in text for n in needles)
        raise TargetProfileError(f"{self.source}: unknown blocked_when rule {rule!r}")

    def _read(self, rule: Dict[str, Any], resp: requests.Response, body: Any) -> Optional[str]:
        if "json" in rule:
            v = _json_path(body, rule["json"])
        elif "header" in rule:
            v = resp.headers.get(rule["header"])
        else:
            v = None
        return None if v in (None, "") else str(v)

    def interpret(self, resp: requests.Response) -> Dict[str, Any]:
        """Normalize the target's answer into the shape attacks/_fire.classify() reads."""
        try:
            body = resp.json()
        except ValueError:
            body = None

        blocked = any(self._matches(rule, resp, body) for rule in self.blocked_when)
        if not blocked and not (200 <= resp.status_code < 300):
            raise TargetInconclusive(
                f"HTTP {resp.status_code} from {self.url} matched no blocked_when rule "
                f"(check the profile's path, auth headers and blocked_when)")

        out: Dict[str, Any] = dict(body) if isinstance(body, dict) else {}
        if not isinstance(body, dict):
            out["body"] = resp.text[:_MAX_BODY_CHARS]
        out["status"] = "blocked" if blocked else "completed"
        out["shield_held"] = blocked
        out["http_status"] = resp.status_code
        out["target"] = self.name
        depth = self._read(self.depth_rule, resp, body)
        out["penetration_depth"] = depth.lower() if depth else ""
        blocked_by = self._read(self.blocked_by_rule, resp, body)
        if blocked_by:
            out["blocked_by"] = blocked_by
        return out
