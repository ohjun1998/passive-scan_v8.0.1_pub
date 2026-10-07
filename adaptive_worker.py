"""Model-proposed, policy-checked HTTP steps for an explicitly configured URL."""

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request


MAX_STEPS = 5
MAX_VALUE = 80
MAX_BODY = 16_384
BRIEF_FIELDS = ("hypothesis", "procedure", "decision_rule")
BLOCK_VALUE = re.compile(
    r"(?i)(?:https?://|javascript:|data:|\b(?:union|select|sleep|benchmark|drop|alter|insert|update|delete)\b|--|/\*|\*/|[;\r\n\x00])"
)


def capabilities(config, url):
    raw = config.get("worker_capabilities", {}).get(url)
    if not isinstance(raw, dict):
        return None
    methods = raw.get("methods", [])
    identities = raw.get("identities", ["anonymous"])
    query_keys = raw.get("query_keys", [])
    form_fields = raw.get("form_fields", [])
    if (not isinstance(methods, list) or not methods or
            set(methods) - {"GET", "POST"} or
            not isinstance(identities, list) or not identities or
            set(identities) - {"anonymous", "a", "b"} or
            any(not isinstance(values, list) or
                any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,39}", value)
                    for value in values)
                for values in (query_keys, form_fields)) or
            ("POST" in methods and not form_fields)):
        raise ValueError("Invalid worker capability declaration")
    return {"methods": methods, "identities": identities,
            "query_keys": query_keys, "form_fields": form_fields,
            "max_steps": min(MAX_STEPS, max(1, int(raw.get("max_steps", 2))))}


def validate_changes(changes, permitted):
    if not isinstance(changes, list) or len(changes) > 5:
        raise ValueError("Too many worker parameters")
    result = {}
    for item in changes:
        if not isinstance(item, dict) or set(item) != {"key", "value"}:
            raise ValueError("Invalid worker parameter")
        key, value = item["key"], item["value"]
        if (key not in permitted or key in result or not isinstance(value, str)
                or len(value) > MAX_VALUE or BLOCK_VALUE.search(value)):
            raise ValueError("Worker parameter outside approved field or value limits")
        result[key] = value
    return result


def validate_brief(brief):
    """Keep the generated prompt as bounded task data, never an execution policy."""
    if not isinstance(brief, dict) or set(brief) != set(BRIEF_FIELDS):
        raise ValueError("Invalid generated test brief")
    if any(not isinstance(brief[key], str) or not brief[key].strip()
           or len(brief[key]) > 500 or "\x00" in brief[key]
           for key in BRIEF_FIELDS):
        raise ValueError("Invalid generated test brief field")
    return {key: brief[key].strip() for key in BRIEF_FIELDS}


def execute_step(client, url, capability, step):
    """Execute one proposed request after checking each field independently."""
    method = step.get("method")
    identity = step.get("identity")
    if method not in capability["methods"] or identity not in capability["identities"]:
        raise ValueError("Worker method or identity is not approved")
    parts = client.policy.validate(url, resolve=True, live=True)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    changes = validate_changes(step.get("changes"), capability["query_keys"] if method == "GET"
                               else capability["form_fields"])
    headers = {"User-Agent": "PassiveScan-Authorized-AI-Review/0.1",
               "Accept": "text/html,application/json"}
    if identity != "anonymous":
        token = client.credentials.get(identity)
        if not token:
            raise ValueError("Worker test-account token is missing")
        headers["Authorization"] = f"Bearer {token}"
    if method == "GET":
        # The model may alter only explicitly named keys on this exact URL.
        if any(sum(key == existing for existing, _ in query) > 1 for key in changes):
            raise ValueError("Ambiguous duplicate query key in worker URL")
        pairs = [(key, changes.pop(key, value)) for key, value in query]
        pairs.extend(changes.items())
        target = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(pairs)))
        body = None
    else:
        if not changes:
            raise ValueError("POST worker step requires approved form fields")
        target = url
        body = urllib.parse.urlencode(changes).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    client.policy.validate(target, resolve=True, live=True)
    client.policy.budget(parts.hostname.lower())
    request = urllib.request.Request(target, data=body, headers=headers, method=method)
    try:
        response = client.opener.open(request, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read(MAX_BODY + 1)
        status = response.status if hasattr(response, "status") else response.code
        # Keep the values inside the protected report, never an Actions summary.
        observation = {"action": "worker_" + method.lower(),
                       "url": parts._replace(query="").geturl(), "status": status,
                       "method": method, "identity": identity,
                       "request_fields": step["changes"],
                       "content_type": response.headers.get("Content-Type", "")[:120],
                       "headers": {}, "body_sha256": hashlib.sha256(raw).hexdigest(),
                       "body_length_at_least": len(raw), "body_truncated": len(raw) > MAX_BODY,
                       "preview": raw[:1200].decode("utf-8", "replace")}
        return observation, raw


def run_worker(config, url, report, planner, client, direction="", planner_context=None):
    """Iterate model-proposed steps, stopping on the same global HTTP budget."""
    cap = capabilities(config, url)
    if cap is None:
        raise ValueError("No worker capability for URL")
    parts = urllib.parse.urlsplit(url)
    brief_context = {
        "selected_asset": {"path": parts.path,
                           "query_keys": [key for key, _ in urllib.parse.parse_qsl(parts.query)],
                           "categories": report["categories"],
                           "test_candidates": report["test_candidates"]},
        "planner_direction": str(direction)[:300],
        "approved_capability": cap,
        "prior_facts": report["facts"][-20:],
        "prior_leads": (report["findings"] + report.get("worker_leads", []))[-20:],
        "shared_progress": planner_context or {},
    }
    brief = validate_brief(planner.draft_test_brief(brief_context))
    report["test_brief"] = brief
    stop_reason = "step_limit"
    for step_number in range(1, cap["max_steps"] + 1):
        if client.policy.request_count >= client.policy.max_requests:
            stop_reason = "request_budget"
            break
        history = [
            {"evidence_id": f"obs-{index}", "action": obs["action"],
             "status": obs["status"], "content_type": obs.get("content_type", ""),
             "body_sha256": obs.get("body_sha256", ""),
             "preview": obs.get("preview", "")[:500]}
            for index, obs in enumerate(report["observations"], 1)]
        parts = urllib.parse.urlsplit(url)
        situation = {"path": parts.path,
                     "query_keys": [key for key, _ in urllib.parse.parse_qsl(parts.query)],
                     "generated_test_brief": brief,
                     "capability": cap, "observations": history,
                     "remaining_requests": client.policy.max_requests - client.policy.request_count}
        proposal = planner.propose_step(situation)
        if proposal.get("kind") == "stop":
            valid = {entry["evidence_id"] for entry in history}
            ids = proposal.get("evidence_ids", [])
            if not isinstance(ids, list) or any(value not in valid for value in ids):
                raise ValueError("Worker lead references unavailable evidence")
            if ids:
                report.setdefault("worker_leads", []).append({
                    "kind": str(proposal.get("lead_kind", ""))[:80],
                    "status": "manual_review", "confidence": "inferred",
                    "reason": str(proposal.get("reason", ""))[:300],
                    "evidence_ids": ids})
            stop_reason = "worker_stop"
            break
        if proposal.get("kind") != "request":
            raise ValueError("Unknown worker step")
        report["plans"].append({"action": "worker_" + str(proposal.get("method", "")).lower(),
                                "question": str(proposal.get("reason", ""))[:300],
                                "expected": str(proposal.get("expected", ""))[:300],
                                "confidence": "inferred", "worker_step": step_number})
        observation, raw = execute_step(client, url, cap, proposal)
        # Redact before sending observations back to the model or storing them.
        from ai_review import sanitize
        observation["preview"] = sanitize(observation["preview"])
        report["observations"].append(observation)
        if status := observation["status"]:
            if status == 429 or status >= 500:
                stop_reason = "halted_on_server_signal"
                break
    return stop_reason
