"""Record an already-authorized model call, then replay its exact bound response.

Place the recording provider behind ModelBridge/InferenceReceiver. This class
does not grant egress and never initiates calls during replay.
"""
from atomicroot.authority.ticket import args_hash, freeze_json
from threading import Lock
from atomicroot.observability import Stopwatch


class ModelTape:
    def __init__(self, *, provider, model, prompt_version, records=None, delegate=None):
        if not all(type(x) is str and x for x in (provider, model, prompt_version)):
            raise ValueError("provider/model/prompt binding required")
        self.provider, self.model, self.prompt_version = provider, model, prompt_version
        self.delegate = delegate
        if delegate is not None and (delegate.provider, delegate.model) != (provider, model):
            raise ValueError("recording delegate binding mismatch")
        self.live = bool(delegate and delegate.live)
        self.mode = "live" if self.live else "replay" if delegate is None else "fake"
        self.structured_worker_output = bool(getattr(delegate, "structured_worker_output", False) or
            (delegate is None and any(r.get("binding", {}).get("response_schema") is not None for r in (records or {}).values())))
        self.records = freeze_json(records or {}, max_bytes=16 * 1024 * 1024)
        self.ordinals, self.lock = {}, Lock()
        source = getattr(delegate, "execution_binding", None) if delegate else args_hash(self.records)
        self.execution_binding = args_hash({"provider": provider, "model": model, "prompt": prompt_version,
                                           "tape_schema": 1, "source": source}) if source is not None or self.live else None

    def binding(self, messages, response_schema=None):
        return {"tape_schema": 1, "provider": self.provider, "model": self.model,
                "prompt_version": self.prompt_version, "context_digest": args_hash(messages),
                "response_schema": response_schema, "schema_digest": args_hash(response_schema),
                "messages": freeze_json(messages)}

    async def generate(self, messages, *, response_schema=None):
        binding = self.binding(messages, response_schema)
        context = args_hash(binding)
        with self.lock:
            ordinal = self.ordinals.get(context, 0)
            self.ordinals[context] = ordinal + 1
        binding["ordinal"] = ordinal
        key = args_hash(binding)
        previous = self.records.get(key)
        if previous:
            if previous["binding"] != binding: raise ValueError("model tape record binding mismatch")
            if "error" in previous: raise RuntimeError("recorded model failure: " + previous["error"])
            if previous["response_digest"] != args_hash(previous["response"]):
                raise ValueError("model tape record binding mismatch")
            return freeze_json(previous["response"])
        if self.delegate is None: raise ValueError("no exact context/model/schema/prompt replay record")
        timer = Stopwatch()
        try:
            response = await self.delegate.generate(messages, response_schema=response_schema) if response_schema is not None else await self.delegate.generate(messages)
            response = freeze_json(response)
        except Exception as exc:
            # Do not serialize provider exception bodies, credentials or URLs.
            self.records[key] = {"binding": binding, "error": type(exc).__name__, "observed_timing": timer.finish()}
            raise RuntimeError("recorded model failure: " + type(exc).__name__) from None
        self.records[key] = {"binding": binding, "response": response, "response_digest": args_hash(response), "observed_timing": timer.finish()}
        return freeze_json(response)
