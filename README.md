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

This interface stores workflow and acceptance descriptors. It does not provide
a general task executor or a goal-to-execution LLM planner.

## Source layout

- `atomicroot/authority`, `gateway`, and `store`: authorization and versioned state.
- `atomicroot/framework`: contracts, approvals, labels, task configuration, and outbox.
- `atomicroot/integration`: guarded workflows, model providers, and classification.
- `atomicroot/tests`: offline mechanism and regression tests.

Run directories can contain signing keys, prompts, documents, and provider
responses. They are excluded from Git along with internal development notes
and generated experiment reports.
