# Hasil aktual Fase 5.5

Tanggal lokal pengguna: **28 Oktober 2026, Asia/Jakarta**. Status:
**implemented dan offline verified**. Live B/provider/policy synthesis/JEV
validation **NOT RUN**; business effects **SIMULATED**. Tidak melanjutkan Fase 6.

## Perubahan dan alasan

- `integration/goals.py` menambahkan trusted intake, discovery, proposal/review,
  bounded replan, execution A dan versioned protected exports. Kontrak hasil
  planning tidak dapat mengotorisasi planning call sebelumnya.
- `integration/planning.py` menambahkan prompt/schema/parser proposal v1 dan
  binding planner context. LLM menyusun TaskSpec/workflow/DSL; bukan memilih
  cabang scenario atau menciptakan tool/label/authority baru.
- `atomicroot_cli.py` menjadi CLI utama B; optional HTTP goal routes menggunakan
  identity resolver dan trusted executor factory API yang sama. A tetap jalur
  konfigurasi internal/replay dan CLI lama dipertahankan.
- `TaskService.propose` menerima trusted review bindings opsional. Hash origin
  proposal, latest revision dan execution-control versions ikut basis Broker;
  proposal berubah/superseded membuat approval stale.
- Protected model context/ModelBridge/Gateway diperluas untuk planner. Ticket
  expiry dibatasi expiry intake. Actual intake TaskSpec digest, endpoint dan
  call/token/spend limits direkam serta masuk model context; replay cap/endpoint
  divergence ditolak.
- InferenceMemo menambahkan optional aggregate session budget. B memakai satu
  budget untuk planner/repair/worker/classifier/retry; A lama tetap memakai
  perilaku default. Live paid planner/worker tidak berjalan tanpa spend bounds.
- Executor A memperoleh bound completed-node carryover untuk reviewed plan
  revision. Receipt/checkpoint evidence dipertahankan; tidak menjalankan ulang
  completed business effects, termasuk crash sebelum checkpoint revisi pertama.
- `run_tests.py phase55` dan generator Fase 5.5 ditambahkan ke profil `all`.
  Tidak ada dependency, provider, framework, backend atau evaluator policy baru.

Schema database additive: `goal_sessions`, `goal_revisions`, `goal_calls`,
`execution_carryover`. Tidak ada penghapusan tabel atau reset ledger/budget/taint.
Seluruh writer memakai transaction/admission yang sudah ada. Audit requirement
→ source → test tersedia pada [README](README.md).

## Command dan hasil

Command baseline yang benar-benar dijalankan:

```powershell
.\.venv\Scripts\python.exe -m pytest atomicroot/tests -q --junitxml=.runs/phase55/baseline.xml
```

Hasil: **512 passed**, 0 failures/errors/skips. JUnit mencatat 55,806 detik.

Verifikasi akhir seluruh source:

```powershell
.\.venv\Scripts\python.exe run_tests.py all --output .runs/testing/phase55-final-verification
.\.venv\Scripts\python.exe run_tests.py phase55 --output .runs/testing/phase55-profile-verification
git diff --check
```

| Pemeriksaan | Hasil aktual |
| --- | --- |
| Final regression | **552 passed**, 0 failure/error/skip; pytest JUnit 81,634 detik |
| Test khusus Fase 5.5 | **40 passed**; termasuk API/CLI, model worker, replay caps dan continuation crash |
| Profil `phase55` | **47 passed**: 40 Fase 5.5 + 7 timestamp tests |
| Generator Fase 4 | 34 skenario + satu fallback = **35 exact replay cocok** |
| Generator Fase 5 | 13 skenario × enam mode = **78 exact replay cocok** |
| Generator Fase 5.5 | **2 goal SATISFIED**, 2 fresh-key initial proposal replay cocok, checkpoint recovery tanpa duplicate |
| Negative B artifacts | Unsupported, forged authority, stale review: **0 business intent** |
| CLI PowerShell end-to-end | Init fixture → bootstrap review → goal planning/review → execution/recover/export: **PASSED** |
| Whitespace/diff | `git diff --check` lulus |

Actual executable/args, UTC windows, exit codes, JUnit dan log per command:
`.runs/testing/phase55-final-verification/summary.json`, `plan.json`,
`progress.jsonl`, `regression.xml`, serta log masing-masing generator. Machine
report yang dapat ditinjau: [test-results.json](test-results.json).
Replay bukan independent trial tambahan atau benchmark performa terkontrol.

CLI walkthrough juga benar-benar dijalankan melalui proses Python/PowerShell,
bukan hanya pemanggilan fungsi test. Hasil lokal berada pada
`.runs/phase55/cli-acceptance/execution.json`, `recovery.json`, dan private export.
Keduanya berstatus `SATISFIED`. Signing key lokal CLI tidak dimasukkan ke artifact.

## Demonstrasi positif dan negatif

**Berhasil — goal baru untuk guarded write**

Input goal:

> Read the file and write a proposed update after a fresh read, with amount at most 175.

Fake planner menghasilkan dua node, read lalu write, scope/delegasi eksplisit,
policy DSL `goal_amount_limit`, dan acceptance receipt `update_document`.
Proposal melewati resolver/compiler, pause, approval dan activation. Worker
menggunakan actual delivered read receipt, bukan ID yang dikarang. Output:
`SATISFIED`, criterion receipt satisfied, quality `NOT_EVALUATED`.

State awal `document:file` content version 1. Accepted write menghasilkan
version 2 dengan content `Synthetic B output`; label versi baru UNKNOWN.
Terdapat dua business outbox rows: read dan write, dengan receipt nyata receiver
simulasi. Recover tidak menambah logical effect. Artifact:
`.runs/testing/phase55-final-verification/phase55/goal-2/goal-artifact.json`.

**Ditolak — proposal mengaku memiliki approval**

Input fixture menambahkan field `approved_by: "user approved"` pada proposal.
Parser menolak field authority yang tidak didukung. Sesudah satu repair bound,
status `INVALID_PROPOSAL`; `contract3:write-a` tetap tidak aktif, dokumen tetap
version 1 dan tidak ada business outbox. Planning fake calls tetap dicatat;
"nol business intent" tidak berarti planning call dihapus dari ledger.
Artifact: `phase55/forged-authority/goal-artifact.json` pada folder run final.

**Ditolak — review stale**

Trusted owner fixture mengubah content setelah preview, sebelum approve.
Broker menolak dengan `STALE_REVIEW_REJECTED` pada validation report; dokumen
menjadi version 2 akibat mutasi owner, bukan efek worker. Tidak ada business
contract aktif atau business intent. Owner fixture terpisah dari attacker.

Test tambahan membuktikan policy yang lolos DSL benar-benar dievaluasi Z3:
custom constraint document version menghasilkan `DENY`, bukan sekadar schema
valid. Ini fixture enforcement; tidak diklaim sebagai synthesis model live.

## Kegagalan percobaan yang dipertahankan

| Bukti mentah | Kegagalan dan perbaikan |
| --- | --- |
| `.runs/phase55/targeted-initial.xml` | 1/1 test gagal: scripted read node tidak mengusulkan done dan mencapai retry bound. Fixture diperbaiki; bound executor dipertahankan. |
| `.runs/phase55/targeted-third.xml` | 1/20 test gagal: test mengharapkan raised exception, sedangkan service merekam `PLANNING_FAILED/PermissionError`. Assertion diperbaiki sesuai API, tetap memeriksa nol tambahan model call. |
| `.runs/phase55/targeted-sixth.xml` | 1/37 test gagal: fake model mengulang output, tidak berpindah ke done setelah `OUTPUT_STORED`. Fixture dibuat stateful. |
| `.runs/testing/phase55-final/summary.json` | Cleanup menghapus import `json`; 31 assertion gagal dan generator B gagal tertutup sebelum provider calls. Import dipulihkan. Run gagal ini tidak ditimpa. |

Automatic approval review sempat tidak dapat berjalan karena usage limit;
aksi tidak dieksekusi pada percobaan tersebut. Setelah pengguna melanjutkan,
perbaikan dan verifikasi dijalankan normal. Itu bukan keputusan bahwa tindakan
tidak aman. Hasil hijau terbaru berasal dari run terpisah yang disebut di atas.

## Batas dan pekerjaan yang belum dijalankan

- Live smoke **NOT RUN**: environment aktif tidak mempunyai `GROQ_API_KEY`,
  `GROQ_MODEL`, `OPENAI_API_KEY`, `OPENAI_MODEL`, atau `OLLAMA_MODEL` yang
  dikonfigurasi. Hanya presence boolean diperiksa; nilai rahasia tidak dicetak.
  Tidak ada paid/provider call dicoba atau diganti menjadi fake success.
- Semua proposal contoh/test berasal dari fake/prebuilt fixture atau exact
  replay. Integrasi planner siap menerima model yang disahkan, tetapi kualitas
  planning dan policy synthesis live belum diverifikasi.
- Original goal/context immutable per session. Maksimum satu repair dan dua
  replan; scope/plan/acceptance material perlu review. Acceptance/policy asli
  tidak boleh diam-diam dihapus. Completed business node/agent harus tetap sama;
  pending/UNKNOWN delivery harus direkonsiliasi sebelum revisi aktif.
- Initial replay memakai fresh prepared runtime/intake dan protocol baru;
  later-revision replay berupa frozen response verification/resolution A.
  Tidak mengembalikan historical ledger/grants atau mengklaim seluruh live
  replanning trace identik. Divergence explicit, bukan security normalization.
- Default goal 2048 bytes dan total server context 8192 bytes; schema/DAG,
  resource, call/token/time/spend limits tetap bounded. Tidak ada silent truncate
  atau fallback ke plan yang diam-diam dianggap approved.
- Generalitas dibatasi adapter/fact/operator/acceptance terdaftar. Tidak perlu
  template per use case, tetapi model tidak memasang arbitrary tool/code.
  Origin mapping dan valid DSL tidak membuktikan kesesuaian seluruh maksud user.
- Authentication/fixtures masih trusted local host; SQLite WAL satu writer dan
  fallback single-process/database tetap berlaku. Tidak ada claim distributed
  lock, unconditional liveness, exactly-once provider billing atau universal safety.
- Tidak menjalankan Fase 6, full/adaptive attack benchmark, provider/framework/
  backend baru, real email/payment/deploy, training classifier, atau formal proof.
