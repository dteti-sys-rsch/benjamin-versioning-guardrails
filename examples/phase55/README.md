# AtomicRoot Fase 5.5 — Goal, discovery, synthesis dan execution B

Status: implemented dan offline verified dengan fake/replay model. Smoke live
Ollama Qwen3:8b pada 28 Oktober 2026 memverifikasi worker A dan recovery.
Planner B sudah dicoba live tetapi belum menghasilkan proposal executable;
policy synthesis live belum berhasil diverifikasi. JEV live **NOT RUN**. Effects bisnis tetap simulasi.
Fase 6 tidak dijalankan. Z3 tetap satu-satunya evaluator policy aktif.

## Bentuk sistem

`atomicroot_cli.py` menjadi jalur utama B. Alurnya: goal bahasa bebas → catalog
yang boleh dilihat → proposal LLM berupa TaskSpec/agent/workflow/DSL → resolver
A → preview → review Broker → aktivasi → executor A → completion evidence.
Runtime tidak memilih template berdasarkan nama goal. Model dapat menyusun
kombinasi baru dari adapter, operator, fakta dan acceptance criteria terdaftar.
Ini tidak berarti semua use case atau semua maksud bahasa alami dapat dijamin.

`GoalService` menerima driver model yang dipilih trusted composition root.
Pengguna/worker tidak dapat memasok principal, approver, updater, provider atau
kode executable dalam proposal. Planner menghasilkan `PROPOSAL`, `CLARIFY`,
atau `UNSUPPORTED`; fields tidak dikenal dan unsupported policy gagal tertutup.
Valid schema/DSL tidak membuktikan minimal scope atau kesesuaian maksud secara
sempurna. Origin mapping mengutip goal dan menunjuk field proposal. Scope yang
tidak dirujuk registered completion criteria/dependency diberi warning review.

## Audit requirement → fondasi → perubahan

| Requirement | Fondasi yang dipakai kembali | Gap / bukti Fase 5.5 |
| --- | --- | --- |
| Bootstrap planning sebelum business contract | TaskService, Broker, protected `model_inference`, InferenceMemo | Reviewed intake task terpisah, admin `goalintake` config, expiry dan visibility. `goals.py`, `planning.py`, `egress.py`; tests caller/provider/expiry/sensitive egress. |
| Metadata discovery, content read terpisah | Entitlement relations dan trusted catalog | Intersection visibility dengan scope parent. Content opsional melalui guarded read sebelum tersedia; exposure tercatat. Test `test_authorized_context_read_is_exposed_before_planner_and_untrusted`. |
| Dynamic TaskSpec/plan/DSL | TaskSpec/compiler/dependency/Z3 A | Planner prompt/schema v1, parser, satu repair maksimum, origin mapping dan unsupported. Tests invalid tool/fact/operator/identity/label/cycle serta dua goal berbeda. |
| Exact preview/review | TaskService.propose dan Broker exact hash/basis/expiry | Goal head/proposal/execution-control versions masuk resolved basis. Origin mapping, catalog dan goal digest terikat pada review. Superseded/stale/tampered review ditolak. |
| Guarded execution dan completion | ConfigWorkflow/GuardedTools, outbox, server receipts | `GoalService.execute` memakai executor A yang sama. Scripted dan model-worker tests sampai SATISFIED, recover tidak menduplikasi efek. |
| Replan bounded dan tidak menurunkan target | Reviewed activation dan operation ledger A | Maksimum dua replan; original goal/context immutable, acceptance dan policy sebelumnya dipertahankan. Scope/budget/policy/plan berubah memakai preview/review baru. |
| Committed effect dan staged identity | Atomic intent/outbox dan checkpoint A | Completed business nodes dipertahankan bersama source checkpoint/receipt binding; recovery sebelum checkpoint pertama tidak mengulang efek. Pending/UNKNOWN harus direkonsiliasi dahulu. Cancel uncommitted stages dicatat eksplisit; tidak mengedit payload/ID lama. |
| Planning crash/caps/memo | InferenceMemo dan ModelTape | `recover-plan` memakai call/job/context yang sama. Planner, worker, repair, retries dan classifier berbagi session call/token/spend budget; default A non-goal tidak berubah. |
| Recording/replay dan privacy | ModelTape, protected local ledger, Progress | Artifact v1, raw recorded proposals/responses, revision history, schemas, catalog/input/version binding. Fresh prepared replay wajib; cached session tidak dianggap replay. Public status/progress tidak membawa raw goal/prompt/response. |
| API/CLI utama B | Existing FastAPI identity resolver dan executor factory | Optional goal routes di `create_phase3_app`; primary `atomicroot_cli.py`; A CLIs tetap kompatibel. HTTP/CLI tests memakai trusted authentication fixture. |

Source baru: `atomicroot/integration/goals.py`, `planning.py`, `atomicroot_cli.py`.
Test utama: `atomicroot/tests/test_phase55_goals.py`. Tidak ada dependency,
backend, framework, policy evaluator atau provider baru.

Schema DB additive: `goal_sessions`, `goal_revisions`, `goal_calls`, dan
`execution_carryover`. Control keys: `goalintake`, `goalhead`, `goalproposal`,
`goalexecuting`; semua mutasi melewati transaction/admission store yang sama.
Control keys ini bukan arbitrary fact source baru yang dapat dipilih model.
Registry DSL/operator lama tetap dipakai; tidak ada reset budget/exposure.

## Intake dan batas data

Admin menyiapkan resource/destination/parent entitlement dan TaskSpec intake
khusus read/model inference, lalu intake direview/diaktifkan melalui A. Setelah
itu `register-intake` mengikat subject, target tasks, planner agent, context
resource, provider/model/purpose, visibility, expiry dan repair/replan bounds.
Business contract hasil planning tidak mengotorisasi planning call sebelumnya.

Server context tetap UNKNOWN. Provider harus secara eksplisit mengizinkan
UNKNOWN untuk context tersebut; ini bukan promosi goal menjadi PUBLIC. Content
resources memerlukan read scope dan inference scope sendiri. SENSITIVE exposure
tidak bisa dikirim jika provider tidak memiliki izin SENSITIVE. Exposure intake
bersifat konservatif lintas sesi yang memakai task intake sama; tidak direset.

Gateway membaca `goalintake` dari snapshot yang sama dan memasukkan versinya ke
footprint. Expiry tiket planner dibatasi expiry intake, sehingga expiry/revocation
antara authorization dan commit tidak dapat membuka call. Endpoint/model juga
harus sesuai reviewed catalog. Tidak ada network/inference/review manusia di
dalam transaksi atau fallback gate. File invocation lock executor hanya menjaga
satu orchestration invocation; bukan lock business state.

Caps konfigurasi contoh: 12 calls/session total, 200000 conservative token
allowance, 4096 output tokens/call, timeout 30 detik/call, retries 0. Maksimum
satu repair dan dua replan; seluruhnya memakai budget yang sama. Angka ini bound
fixture, bukan hasil tuning performa. Paid live memerlukan explicit authorization
serta pricing/spend cap yang diverifikasi host. JEV opsional tetap memakai
classification proposal/acceptance A; tidak ada training atau label authority baru.

## Menjalankan verifikasi sekali jalan

```powershell
.\.venv\Scripts\python.exe run_tests.py phase55
.\.venv\Scripts\python.exe run_tests.py all
.\.venv\Scripts\python.exe examples/phase55/generate.py --output .runs/my-b-evidence
```

Generator menghasilkan dua goal dengan workflow berbeda, review/pause,
execution/completion, checkpoint recover, fresh-key proposal replay, serta
artifact negative `unsupported`, `forged-authority`, dan `stale-review` tanpa
business intent. Proposal generator berasal dari **fake/prebuilt fixture**,
bukan bukti model live melakukan synthesis. Model-worker tests memakai fake
model stateful melalui protected inference yang sama.

## Live Ollama Qwen3:8b

Perbaikan lanjutan memakai prompt `goal-planner-v6`: structured planner grammar,
feedback draft/path, validasi context dan scope, serta receipt-based completion
untuk beberapa node dengan agent sama. Schema generation direkonstruksi host dan
tetap dihitung dalam budget; batas context 8192 byte dipertahankan. Perubahan
prompt/schema menyebabkan divergence artifact lama secara eksplisit, tanpa
menghapus binding agar replay tampak cocok.

Kontrol dua node tersedia melalui `--case worker-multi`. Synthesis B tetap belum
berhasil untuk read/summary pada sampel live; proposal invalid tidak dilonggarkan.
Lihat [laporan perbaikan](../../docs/REPORTS/PHASE_55_PLANNER_FIX_REPORT.md)
untuk hasil aktual, termasuk percobaan gagal.

Dari root repository, dengan Ollama lokal dan `qwen3:8b` sudah tersedia:

```powershell
# Kontrol A: keputusan worker benar-benar berasal dari Qwen. Plan disiapkan host.
.\.venv\Scripts\python.exe examples/phase55/live_ollama.py --output .runs/my-qwen-worker --authorize-live --fixture-approve --case worker-control

# B: goal bahasa alami masuk ke planner Qwen, tanpa proposal fixture pengganti.
.\.venv\Scripts\python.exe examples/phase55/live_ollama.py --output .runs/my-qwen-planner --authorize-live --fixture-approve
```

Gunakan output directory baru. `--fixture-approve` hanya mengizinkan reviewer
sintetis dalam demo ini; bukan approval dari model atau authentication produksi.
Parent rights hanya read dan inference ke loopback Ollama, tanpa update, email,
payment atau provider remote. Sumber kontrol berupa catatan benchmark rekaan.
Tidak ada model pull, cloud fallback, JEV, atau real business effects.

Batas per session: 8 inference attempts, conservative token allowance 200000,
3072 output tokens/call, timeout 120 detik/call, network retries 0, satu planner
repair dan nol replan. Adapter memakai `think=false`, context 16384 dan
temperature 0. Timeout tidak membuktikan provider tidak sempat memproses input.

Output mencakup `summary.json`, salinan `runner.py` dan hash, timestamp UTC,
fixture/spec, ledger SQLite, `progress.jsonl`, `initial-state.json`,
`final-state.json`, preview serta artifact/transcript jika tersedia. Signing
keys hanya di memori; checkpoint recovery diperiksa dalam invocation demo yang
sama. Ini bukan perintah resume CLI untuk ledger yang key-nya tidak disimpan.

Hasil aktual 28 Oktober 2026: kontrol A terakhir `SATISFIED`, 2 calls live,
recovery tanpa call/intent baru. Empat session planning B belum menghasilkan
proposal executable (provider crash, timeout, dua CLARIFY setelah proposal
invalid). Exit code 1 pada B menyatakan kriteria demo belum tercapai; hasil
negatif tetap disimpan dan tidak diganti fake response. Offline default tetap
tidak memanggil model. Lihat [laporan Qwen](../../docs/REPORTS/PHASE_55_OLLAMA_QWEN3_8B_REPORT.md).

## Alur CLI lokal yang dapat ditinjau

Gunakan direktori run baru. Contoh ini memakai synthetic fixtures dari output
generator; CLI tidak memilih use case secara otomatis. PowerShell dari root:

```powershell
$evidence = '.runs/my-b-evidence'
$run = '.runs/my-b-cli'
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run init-fixture "$evidence/trusted-fixture.json"

# Review bootstrap intake, memakai jalur A yang sama.
$p = .\.venv\Scripts\python.exe phase36_cli.py --directory $run preview "$evidence/intake-spec.json" | ConvertFrom-Json
$p.preview | ConvertTo-Json -Depth 30
.\.venv\Scripts\python.exe phase36_cli.py --directory $run decide $p.review_id approve
.\.venv\Scripts\python.exe phase36_cli.py --directory $run activate $p.proposal_id $p.review_id
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run register-intake "$evidence/intake-permission.json" --ttl 3600

# Explicit offline model-response fixture; live uses a separately approved model.
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run --proposal "$evidence/goal-1/proposal-fixture.json" plan my-goal planning write-a --goal 'Read the file only.'
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run preview my-goal
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run decide my-goal pause
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run decide my-goal approve
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run activate my-goal

$spec = (Get-Content "$evidence/goal-1/proposal-fixture.json" -Raw | ConvertFrom-Json).spec
@{ inspect = @(@{ kind='action'; tool='read_document'; args=@{resource='file';digest=$spec.resources[0].digest} }) } | ConvertTo-Json -Depth 8 | Set-Content "$run/responses.json" -Encoding utf8
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run execute my-goal --responses "$run/responses.json"
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run execute my-goal --responses "$run/responses.json" --command recover
.\.venv\Scripts\python.exe atomicroot_cli.py --directory $run export my-goal "$run/private-goal-artifact.json"
```

`approve`, `reject` dan `pause` adalah alternatif tindakan manusia; jangan
menganggap pause sebagai approval. Export menolak overwrite file yang sudah ada.
`--ttl` adalah renewal lokal administratif eksplisit, bukan hak planner.

`--planner-mode live --authorize-live` memilih driver Groq/Ollama yang sudah ada
berdasarkan intake yang telah direview. Worker model memakai
`execute --worker-mode live --authorize-live`; provider/caps harus sesuai active
TaskSpec. Jangan mengganti intake fixture `offline-script-v1` dengan live hanya
melalui flag: catalog/TaskSpec/permission harus diperbarui dan direview dahulu.

`recover-plan` memulihkan planning yang crash/ambiguous memakai key/binding
lama; `replan` membuat revision baru dan memerlukan review. Keduanya berbeda
dari `execute --command recover/resume` yang melanjutkan checkpoint A. Replan
tidak menghapus committed intent atau UNKNOWN reservation. Retained business
nodes beserta agent definition harus tetap sama; rencana tidak boleh memanfaatkan
revisi untuk mengeksekusi ulang efek yang telah selesai.

## API dan replay

Trusted composition: `GoalService(runtime, model)` lalu
`create_phase3_app(runtime, identity_resolver, goal_service=service,
goal_executor_factory=factory)`. Factory memakai runtime/database dan checkpoint
path yang konsisten; model/worker dipilih host, bukan request body. HTTP routes:

- `GET /goals/schema`, `POST /goals/discover`, `POST /goals`.
- `GET /goals/{session}` untuk status ringkas; `/preview` untuk owner/approver.
- `POST /goals/{session}/decision`, `/activate`, `/replan`, `/recover-plan`.
- `POST /goals/{session}/execute/{start|recover|resume|status}`.

Request `POST /goals` memiliki exact fields `session`, `goal`, `intake`, `task`,
`context_resources`. Principal berasal dari identity resolver; tidak menerima
header/field role yang dipilih worker. Authentication lokal tetap fixture,
bukan sistem login produksi baru. Public progress ringkas; private preview,
ledger, checkpoint dan exports dapat berisi data sensitif dan tidak untuk publish.

`atomicroot_cli.py schema` dan `artifact-schema` menerbitkan schema v1. Artifact
menyimpan request, allowed catalog, intake/schema/registry/prompt digests, exact
model tape, origin/proposal/preview/review basis, revisions dan execution evidence.
Tidak menyimpan signing key atau credentials. Timestamp UTC observasi terpisah
dari clock protocol; hash artifact adalah integrity binding, bukan attestation.

Replay memerlukan database/session baru dengan trusted fixture/intake dan
current snapshot yang cocok. Initial proposal melalui intake/Gateway baru dan
ModelTape tanpa delegate. Untuk revision berikutnya, replay memverifikasi exact
recorded responses dan previous-proposal context, lalu melakukan **frozen latest
revision resolution** dan fresh review A. Tidak me-rewind ledger, menerapkan
historical grants, atau mengklaim seluruh live replanning/delivery trace identik.
Context/catalog/intake/expiry/schema/registry divergence ditolak. Executor A
menangani checkpoint/effect replay secara terpisah, memakai binding/receipts.

Goal baru maksimum 2048 UTF-8 bytes. Total server context tetap dibatasi 8192
bytes; catalog/prior plan yang tidak muat menghasilkan failure eksplisit tanpa
silent truncation. Repair/replan memiliki bounds di atas. Unsupported requirements
tetap terlihat; origin mapping tidak dapat membuktikan model tidak pernah
menghilangkan maksud bahasa alami. Tidak ada universal-use-case atau formal
safety guarantee dari finite offline suite ini.

Hasil aktual, command, kegagalan percobaan, dan batas live dicatat dalam
[results.md](results.md), [test-results.json](test-results.json), dan folder hasil runner.
