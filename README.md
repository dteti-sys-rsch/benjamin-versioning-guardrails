# AtomicRoot

AtomicRoot is a Python research prototype for preventing stale authorization
in concurrent multi-agent workflows. It binds authorization tickets to the
policy dependencies read from a consistent snapshot and checks their versions
atomically when accepting an operation.

## Authorization model

- Z3 is the only active policy evaluator. Missing or inconsistent facts,
  invalid policies, and solver failures do not produce authorization tickets.
- Signed, single-use tickets bind the caller, task, tool, immutable payload,
  dependency versions, nonce, and expiry.
- The Gateway checks freshness and accepts state changes, ticket consumption,
  events, and outbox intents in one SQLite transaction.
- Reviewed contracts, trusted identities, labels, and operation approvals
  constrain worker capabilities. Worker text is not approval authority.
- External effects are dispatched after intent commit. Commit and delivery
  are distinct; arbitrary providers do not guarantee exactly-once delivery.

SQLite uses WAL and has one physical writer at a time. Independent dependency
keys reduce false freshness conflicts; they do not enable parallel physical
writes. The prototype does not claim to prevent all prompt injection or prove
perfect correspondence between policy and user intent.

## Setup

Requires Python 3.11 or later. From the repository root on Windows:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest atomicroot/tests -q
```

On other platforms, use `.venv/bin/python` after creating the environment with
`python3 -m venv .venv`.

## Offline examples

```powershell
.\.venv\Scripts\python.exe demo.py
.\.venv\Scripts\python.exe phase3_cli.py demo
.\.venv\Scripts\python.exe phase3_cli.py schema
.\.venv\Scripts\python.exe phase35_cli.py --directory .runs/my-review
.\.venv\Scripts\python.exe phase36_cli.py schema
```

The workflow CLI defaults to offline model behavior and interactive review.
Explicit fixture approval is available for synthetic demonstrations:

```powershell
.\.venv\Scripts\python.exe phase35_cli.py --directory .runs/public --fixture-approve --classifier fake --classify
```

Use a separate run directory for each scenario or provider configuration.
Resuming a task preserves its ledger, budget, exposure, and reviewed contracts.
Example policies, contracts, and task specifications are in [examples](examples).

## Model providers

The workflow supports OpenAI, Groq, local Ollama, and a trusted local 9Router
configuration. Optional JEV classification uses TypeSafe. Provider calls send
data to the selected provider and require the applicable host authorization
and explicit usage limits. JEV is a classifier, not the policy authority.

See [.env.example](.env.example) for variable names. Export variables in the
shell; the CLI does not load `.env` automatically. Keep credentials local.
Inspect available options before live use:

```powershell
.\.venv\Scripts\python.exe phase35_cli.py --help
```

Local Ollama model listing requires Ollama at `http://localhost:11434`:

```powershell
.\.venv\Scripts\python.exe phase35_cli.py --directory .runs/ollama-models --provider ollama --list-models
```

Offline tests do not establish live provider validation. Email and transfer
effects in the supplied demonstrations use simulated receivers.

## Explicit task configuration

`phase36_cli.py` validates, resolves, previews, and activates reviewed task
specifications against trusted catalogs and entitlements. Synthetic fixtures
and specifications are in [examples/phase36](examples/phase36).

`phase37_cli.py` executes the approved configuration using the existing
LangGraph and authorization core. It supports finite DAGs, configurable agents,
bounded parallel ready workers, Broker review, durable staged operations, and
completion evidence from actual reads, outputs, and receiver receipts.
It does not provide a goal-to-execution LLM planner.

### Execute configuration A

An activated `.venv` provides Python dependencies; it does not initialize task
entitlements in the ledger. A new directory needs `init-fixture` before preview.
If preview fails, do not reuse IDs from an earlier preview. Approve, reject and pause
are alternative decisions; activate only after approval. Existing resources must
not be initialized again. Expired/stale reviews require a new preview.

Initialize a fresh synthetic fixture directory, then review and activate the
configuration with `phase36_cli.py`. Capture its JSON to reuse IDs without
scrolling. The full preview is saved for human review:

```powershell
$atomicRun = '.runs/config-a-01'
.\.venv\Scripts\python.exe phase36_cli.py --directory $atomicRun init-fixture examples/phase36/trusted-fixture.json
$preview = .\.venv\Scripts\python.exe phase36_cli.py --directory $atomicRun preview examples/phase36/literature.json | ConvertFrom-Json
$reviewId = $preview.review_id
$proposalId = $preview.proposal_id
$atomicTask = $preview.preview.proposal.task_id
$preview | Select-Object status, proposal_id, review_id | Format-List
```

Optional: save and open the complete preview without terminal scroll limits:

```powershell
$previewFile = Join-Path $atomicRun ("preview-$proposalId.json")
$preview | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $previewFile -Encoding UTF8
notepad $previewFile
```

After reading the preview, run **one** decision command:

```powershell
.\.venv\Scripts\python.exe phase36_cli.py --directory $atomicRun decide $reviewId approve
.\.venv\Scripts\python.exe phase36_cli.py --directory $atomicRun decide $reviewId reject
.\.venv\Scripts\python.exe phase36_cli.py --directory $atomicRun decide $reviewId pause
```

Only after approval succeeds, activate and run. Continue each step only after
the previous command succeeds; use a new run ID for a new execution:

```powershell
.\.venv\Scripts\python.exe phase36_cli.py --directory $atomicRun activate $proposalId $reviewId
$atomicRunId = 'script-01'
.\.venv\Scripts\python.exe phase37_cli.py --directory $atomicRun --task $atomicTask --run $atomicRunId --responses examples/phase37/literature-responses.json start
.\.venv\Scripts\python.exe phase37_cli.py --directory $atomicRun --task $atomicTask --run $atomicRunId status
```

This example uses explicit **offline scripted** worker fixtures, with no model
calls. The same executor accepts `payments.json` and `payments-responses.json`.
For guarded fake model inference, use `examples/phase37/trusted-model-fixture.json`
in a fresh directory, review `literature-fake-model.json`, and select
`--worker-mode fake` with the same literature responses. The fixture labels
come from the trusted local owner, not a classifier.

For live local Ollama, review `literature-ollama.json` against the model fixture
and select `--worker-mode live --authorize-live`. This sends the approved
synthetic sources and contexts to `qwen3:8b` at the local Ollama endpoint. The
model chooses worker actions; no author contract call is needed. Live execution
is optional and is not established by offline test success.

`resume` continues a pending Broker review after a trusted decision; it is not
approval. `recover` continues a staged operation after invocation failure.
Use the same directory, task, run ID and worker configuration on restart.
Run/config/driver/schema/prompt/checkpoint bindings prevent incompatible replay.
Failed invocations do not erase terminal run history.

`SATISFIED` means the registered acceptance predicates have ledger evidence.
Summary factual correctness is **NOT_EVALUATED**. `REFUSED`, `INCOMPLETE`,
`REVIEW_WAIT`, `REVIEW_REJECTED`, `DELIVERY_UNKNOWN`, `TIMEOUT`, `UNSUPPORTED`,
`RETRY_EXHAUSTED`, and `FAILED` are distinct outcomes. Email/transfers remain
simulated; COMMITTED is distinct from RELEASED.

Read-only nodes with one workflow node per agent finish when their delegated
required reads have verified RELEASED receipts and observations. The model
still proposes the reads; the host does not synthesize model answers. Mixed
action nodes receive bounded feedback for repeated reads of the same current
content version. New versions always follow normal authorization. Provider
messages expose delivered source text once, with provenance and node-local
remaining criteria. The context size bound remains 8192 bytes.

Leaf business nodes stop when all registered task criteria have actual ledger
evidence, so the model cannot add another send merely while deciding to finish.
Published output IDs are omitted from the immutable generation grammar; all
other fields still match the reviewed schema and runtime authorization.

The read-progress patch uses `config-worker-v3` and `config-executor-v3` run
bindings. Start a new run ID on an already ACTIVE task, for example
`--run uji-02`; old history, exposure and counters are retained. Old run IDs
cannot be resumed across changed prompt/executor bindings.

Model workflow progress lines include UTC timestamps, `total` seconds since
the logger invocation started, and `delta` seconds since its previous event.
The JSONL log adds `session_elapsed_ms` and `since_previous_ms`; existing
per-inference `elapsed_ms` is unchanged. Durations use a monotonic clock and
restart from zero in each new logger invocation, while sequence numbers append.
Concurrent events may interleave: `delta` is not a per-agent/tool duration.

Existing exact resource digest/version references remain pinned. Only a
reviewed resource with `binding: "host_context"` permits trusted runtime context
updates, exclusively for one agent's inference. Every new context still needs
an immutable job binding, snapshot freshness, labels and source/provider scope.
It cannot be used as a read/classification resource or a release permission.
Optional classifier `before_nodes` runs before the selected nodes' first
authorization; PUBLIC/error results cannot promote an official label. An
approved conservative SENSITIVE restriction uses Label Manager atomically.

The HTTP API adds `/tasks/{task}/runs/{run}` and
`/tasks/{task}/runs/{run}/{start|resume|recover}`. The host must configure
`executor_factory`; worker bodies cannot supply a driver, caller identity or
approval. Execution endpoints require the task-owning trusted user.

## Scheduler and replay (Phase 4)

Phase 4 adds dependency-ready finite schedules, versioned replay artifacts,
model response tapes, and an optional bounded contention fallback. Z3 remains
the only policy evaluator, and all supplied effects are simulated.

```powershell
.\.venv\Scripts\python.exe phase4_cli.py list
.\.venv\Scripts\python.exe phase4_cli.py record budget-double-allow .runs/phase4/budget.json
.\.venv\Scripts\python.exe phase4_cli.py replay .runs/phase4/budget.json
.\.venv\Scripts\python.exe examples/phase4/generate.py
```

See [Phase 4 audit, writer coverage, bounds and commands](docs/phases/scheduler-replay.md)
and [versioned examples and validation](examples/phase4/validation.json).
Fallback shares a process-local coordinator across connections to one database;
its exclusive window conservatively pauses all writers in that database.
Independent keys still avoid false CAS conflicts. This is not distributed locking.

## Policy evaluation (Phase 5)

Phase 5 adds the six-family benchmark catalog, a receipt-bound simulated
`update_document` adapter, six isolated comparison modes and an independent
finite-prefix oracle. Main service defaults remain safe; unsafe evaluation
runtimes cannot be exposed as HTTP services or call model providers.

```powershell
.\.venv\Scripts\python.exe phase5_cli.py matrix
.\.venv\Scripts\python.exe phase5_cli.py compare budget .runs/phase5/budget
.\.venv\Scripts\python.exe phase5_cli.py replay .runs/phase5/budget/stateful_non_atomic.json
.\.venv\Scripts\python.exe examples/phase5/generate.py
```

See [Phase 5 policy semantics, mode matrix, oracle and limits](docs/phases/policy-evaluation.md)
and [finite scenario results](examples/phase5/validation.json). These are mechanism
fixtures, not a full benchmark or formal proof. All effects remain simulated.

## Source layout

- [docs](docs/README.md): testing guide, phase notes, providers, roadmap, and design.
- [CLI testing guide](docs/testing/CLI_TESTING.md): commands run from this repository root.
- [reports](reports/README.md): historical verification artifacts and new test output.
- `atomicroot/authority`, `gateway`, and `store`: authorization and versioned state.
- `atomicroot/framework`: contracts, approvals, labels, task configuration, and outbox.
- `atomicroot/integration`: guarded workflows, model providers, and classification.
- `atomicroot/tests`: offline mechanism and regression tests.

Run directories can contain signing keys, prompts, documents, and provider
responses. They are excluded from Git along with internal development notes
and generated experiment reports.
