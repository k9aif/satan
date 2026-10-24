# Target profiles: point SATAN at your own running application

Status: design v1 (2026-10-24). Phase 1 is implemented with this note; phases 2 to 4 are proposals.

## The problem

SATAN's 16 attacks only work against SATAN's own sample application. Every attack POSTs to
`{target}/api/attack/fire` (`attacks/_fire.py`) and expects the sample's response fields
(`status`, `shield_held`, `penetration_depth`). `--target <url>` accepts any URL, but only an
application that copies the sample's private request and response format can answer it, and an
always-on endpoint like that would be a hole in production.

So a security architect at ABC Corp cannot ask the question SATAN exists to answer: *does my
running application, with my prompts, my configuration and my endpoints, hold up?*

## What does not work

**Building the application from its spec.** SATAN would test its own copy, not the deployed
system. The architect's question is about what is running.

**Importing the target's Python classes** (white box). It couples SATAN to the target's internals
and only works for code SATAN can load. A pentest tool talks to the running system over its real
interface.

## Design: a target profile

A target profile is a YAML file that tells SATAN how to talk to a running application over HTTP
and how to read its answers. SATAN never imports or assumes anything else about the target.

```yaml
name: ABC Corp claims assistant
authorized: true                     # you own this system or have written permission to test it
base_url: https://claims.abc-corp.internal
headers:
  Authorization: "Bearer ${TARGET_TOKEN}"     # ${VAR} is read from the environment, never stored here
timeout: 60

request:
  method: POST
  path: /api/chat
  format: json                       # json | multipart
  body:
    message: "{{attack_text}}"
    session: "{{session_id}}"

response:
  blocked_when:                      # any rule matching means BLOCKED
    - status_code: [403, 422, 429]
    - json: { path: blocked, equals: true }
  depth:                             # optional: how far the attack got
    header: X-K9-Blocked-At
  blocked_by:                        # optional: which control stopped it
    json: detail.check
```

### Placeholders

Each attack builds a payload. The profile decides which parts of it reach the target.

| Placeholder | From the attack payload |
|---|---|
| `{{attack_text}}` | `document_text`, the malicious content every attack carries |
| `{{filename}}` | `filename` |
| `{{session_id}}` | `session_id` (memory poisoning, request flood); a fixed per-run id when absent |
| `{{tool_name}}`, `{{tool_arguments}}`, `{{command}}` | structured fields some attacks add |
| `{{correlation_id}}` | `correlation_id` |
| `{{payload}}` | the whole payload, unchanged |

A string that is exactly one placeholder keeps the value's type (a dict stays a dict). A
placeholder with no value becomes an empty string. With `format: multipart`, `file_field` names
the form field that receives `{{attack_text}}` as a file called `{{filename}}`, and `body` holds
the other form fields.

### Outcome rules

Every SATAN payload is malicious by construction, so the rules are deliberately one-sided:

| Target's answer | Outcome |
|---|---|
| A `blocked_when` rule matches | **BLOCKED** |
| No rule matches | **PASSED**: the attack reached output unblocked, a finding |
| Connection error, timeout, or a 5xx not listed in `blocked_when` | **FLAGGED**: inconclusive |

SATAN never reports BLOCKED because it could not tell. An application that answers a malicious
document politely with a 200 has not blocked it.

### Depth

Over the network SATAN sees whether an attack was blocked, not where. `response.depth` reads
the layer (`router`, `orchestrator`, `agent`) from a JSON field or a header when the target
reports it; otherwise depth is `unknown`. Phase 2 makes K9-AIF applications report it.

### The sample application is just the default profile

`targets/satan_sample.yaml` describes SATAN's own sample application through the same adapter:
`body: "{{payload}}"`, `blocked_when: status == blocked`, depth from `penetration_depth`. There
is no special code path for the sample. The attacking side (attacks, runner, report) knows only
profiles; the sample is one target among many. They still ship in one repo and one container,
so satan.k9x.ai is unchanged.

`--target <url>` keeps working: it means the sample profile at that URL.
`--compare-governance` needs a target that accepts `_governance_override`, so it requires a
profile with `response.supports_governance_override: true` (only the sample today).

### Authorization

A tool that fires attacks at any URL is an attack tool against anyone's server. The CLI refuses a
profile without `authorized: true` and prints the target name and URL before the first request.
The hosted version (phase 4) needs proof of ownership, not a flag.

## Phases

1. **Profiles and the HTTP adapter in the CLI** (this change). `fire()` sends through a profile;
   all 16 attack classes are unchanged. Default profile = the sample application.
2. **Depth from K9-AIF applications.** The framework already gives every request a trace id and
   records Shield events. Add an opt-in response header `X-K9-Blocked-At` (and the check name),
   enabled only when `K9_ENV` is development or test, so SATAN can report depth for any K9-AIF
   application without a private endpoint.
3. **Studio writes the profile.** For an application K9X Studio generated, Studio knows the
   endpoints and writes `satan-target.yaml` with the scaffold.
4. **Hosted runs on satan.k9x.ai.** Ownership proof (the target serves a SATAN-issued token at
   `/.well-known/k9x-satan.txt`), the DAS-style job queue (one run at a time, capped per hour),
   and Cloudflare rate limits in front.

## Limits

- Attacks that rely on structured fields (`tool_name`, `tool_arguments`, `command`) only test
  those controls if the target's API accepts such fields and the profile maps them. Against a
  plain chat endpoint they still deliver their text, and the report says so.
- Search poisoning fetches its poisoned text from SATAN's fake search server before firing; the
  text then goes to the target like any other attack.
- `runner/benign_runner.py` (false-positive check) still runs the sample in-process.
