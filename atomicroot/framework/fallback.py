"""Optimistic CAS first; measured stale results trigger bounded fresh fallback."""
from time import monotonic

from atomicroot.authority.ticket import freeze_json
from atomicroot.framework.contention import FallbackConfig, ContentionCancelled, ContentionTimeout
from atomicroot.framework.runtime import validate_request


def commit_fresh(runtime, request, principal, *, grant=None, config=FallbackConfig(), cancelled=None):
    request = validate_request(freeze_json(request), principal)
    store = runtime.store
    deadline = monotonic() + config.timeout
    stale_count, restarts, attempts = 0, 0, 0
    keys = set()
    history = []

    def attempt():
        auth = runtime.authority.authorize(request, principal, grant_id=grant, action_id=request["operation_id"])
        if auth.get("decision") != "ALLOW": return auth, None
        result = runtime.gateway.commit(auth["ticket"], auth["commit_args"], principal, action_id=request["operation_id"])
        return auth, result

    def result(auth=None, commit=None, reason=None):
        return {"authorization": auth, "commit": commit, "reason": reason,
                "attempts": attempts, "stale_count": stale_count, "restarts": restarts, "history": history}

    while attempts < config.max_attempts:
        if cancelled is not None and cancelled.is_set(): return result(reason="CANCELLED")
        if monotonic() >= deadline: return result(reason="CONTENTION_TIMEOUT")
        exclusive = stale_count >= config.stale_threshold
        if not exclusive:
            attempts += 1
            auth, committed = attempt()
        else:
            # Never wait for review/inference/delivery under this gate. Hooks are
            # deferred until release, so instrumentation cannot invert lock order.
            try:
                with store.coordinator.acquire(exclusive=True, keys=keys, timeout=max(.001, deadline - monotonic()), cancelled=cancelled):
                    attempts += 1
                    auth = runtime.authority.authorize(request, principal, grant_id=grant, action_id=request["operation_id"])
                    committed = None
                    if auth.get("decision") == "ALLOW":
                        discovered = set(auth["ticket"]["footprint"]) | set(auth["ticket"]["write_set"])
                        if not discovered <= keys:
                            keys |= discovered
                            restarts += 1
                            history.append({"mode": "fallback", "status": "DEPENDENCY_EXPANDED", "keys": sorted(keys)})
                        else:
                            committed = runtime.gateway.commit(auth["ticket"], auth["commit_args"], principal, action_id=request["operation_id"])
            except ContentionCancelled: return result(reason="CANCELLED")
            except ContentionTimeout: return result(reason="CONTENTION_TIMEOUT")
            finally: store.flush_observations()
            if auth.get("decision") == "ALLOW" and committed is None:
                if restarts > config.max_restarts: return result(reason="DEPENDENCY_RESTART_EXHAUSTED")
                continue
        history.append({"mode": "fallback" if exclusive else "optimistic", "status": (committed or auth).get("status", auth.get("decision")), "keys": sorted(keys)})
        if auth.get("decision") != "ALLOW": return result(auth, reason="AUTHORIZATION_TERMINAL")
        keys |= set(auth["ticket"]["footprint"]) | set(auth["ticket"]["write_set"])
        if committed["status"] != "STALE_TICKET": return result(auth, committed)
        stale_count += 1
    return result(reason="RETRY_EXHAUSTED")
