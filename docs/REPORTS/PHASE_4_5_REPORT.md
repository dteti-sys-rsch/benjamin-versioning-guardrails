# Laporan bukti AtomicRoot Fase 4 dan 5

Tanggal pemeriksaan: 27 Oktober 2026. Status kedua fase: **implemented dan
offline verified** pada skenario yang disebutkan di bawah. Effects simulasi;
validasi live Fase 4–5 **NOT RUN**. Laporan ini tidak menjalankan fase berikutnya.
Laporan dibuat dari source, tests, XML, dan artifact aktual, bukan hanya roadmap.

Path dalam laporan relatif terhadap root repository:
`C:/Main Storage/Documents/UGM/.PROYEK INDIVIDU/System`.

## 1. Yang dibangun dan berubah, beserta alasan

### Fase 4

| Perubahan | Alasan dan bagian yang dipertahankan |
| --- | --- |
| `Action`, `ReadyScheduler`, hook protokol, CLI record/replay/pair | Menentukan interleaving yang dapat diinspeksi. Scheduler hanya memilih action ready; tidak mengandalkan sleep. Snapshot/Z3/CAS fondasi tetap dipakai. |
| Replay schema v1 dan `ReplayHost` | Seed saja tidak menyimpan interleaving, resolved config, state, atau fault. Artifact memuat TaskSpec/plan/delegations/basis, registry/policy/prompt versions, content/labels, IDs, clock, schedule, dan terminal observations. |
| `TestInputs` dan ticket/service ID injection | Mengulang identitas semantik tanpa mengganti crypto RNG produksi. Replay memakai signing key sementara baru, Authority yang sama dan tiket baru. Private key tidak diserialisasi. |
| `ModelTape` | Merekam response/error dari call yang sudah diotorisasi, lalu replay offline dengan exact binding model/context/schema/prompt/digest/ordinal. Bukan klaim provider menghasilkan ulang output identik. |
| `WriterCoordinator`, `FallbackConfig`, `commit_fresh` dan admission semua writer | Mengatasi contention terukur sambil tetap reread, reauthorize dan CAS. Lock hanya pada fallback tanpa koordinasi writer lain tidak cukup. |
| Instrumentation storage, approval, classifier, outbox, executor/checkpoint | Mengekspos boundary yang relevan tanpa menganggap transaksi parsial sebagai commit. Hook di dalam fallback ditunda sampai gate dilepas. |

Tidak ada evaluator policy kedua, backend/dependency baru, atau migrasi tabel DB
pada Fase 4. Perubahan fondasi terbatas pada injection ID/clock, instrumentation,
dan admission writer; approval/outbox/executor yang sudah benar digunakan ulang.

Default tetap optimistic. Fallback bersifat opt-in pada trusted composition root.
Default config: dua hasil `STALE_TICKET` terukur, maksimum empat authorization
attempts, dua dependency restarts, admission budget lima detik. FIFO admission
diambil sebelum connection lock/`BEGIN IMMEDIATE`; concrete keys diurutkan
lexical. Dependency bertambah berarti release/reacquire union dan tiket baru.
`ESCALATE` keluar critical section. Human review, inference/network dan delivery
berada di luar gate/transaksi. Cancellation sebelum attempt/wait dapat
menghentikan admission; commit yang sudah linearized tidak dibatalkan.

Terminal reasons: `AUTHORIZATION_TERMINAL`, `RETRY_EXHAUSTED`,
`DEPENDENCY_RESTART_EXHAUSTED`, `CONTENTION_TIMEOUT`, `CANCELLED`.

### Fase 5

| Perubahan | Alasan dan bagian yang dipertahankan |
| --- | --- |
| Katalog enam family policy dengan applicability, facts/authority/transitions/dependencies/evidence | Memformalkan exfil, budget, delegation, recipient, stale read/write dan once pada typed AST/compiler/Z3 yang sama. Enam family bukan batas permanen DSL. |
| Guarded `update_document` dan `readbasis:{task}:{operation}` | Menutup gap tool write yang sebelumnya belum tersedia. Server receipt mengikat task/agent/resource/version/digest; worker tidak menentukan atau mengosongkan read provenance. |
| Registry/request schema, adapter dan executor wiring untuk write | Menegakkan payload immutable, receipt valid dan atomic content/version/label update melalui Gateway/outbox yang sama. Content maksimum 8192 UTF-8 bytes. |
| `EvaluationAdapter` dan enam mode terisolasi | Membandingkan guard dengan workload/identity/source/arrival/priority/fault plan yang sama. Main service tidak menyediakan switch ke unsafe mode. |
| Global-version instrumentation dan approval binding | Menyediakan baseline global CAS yang mencakup writer dari connection lain, sekaligus menunjukkan false conflict pada key independen. |
| Independent finite-prefix oracle dan intent facts | Menilai accepted intent, applied effects, unknown delivery dan ground-truth leakage dari bukti nyata; tidak memakai keputusan guard sebagai ground truth atau membuat Python DSL evaluator kedua. |
| Union dependency pada respons DENY | Memperbaiki kelengkapan evidence ketika policy lain juga membaca fakta. Union pada ALLOW yang sudah benar dipertahankan. |

Enam mode: `no_guard`, `stateless_per_action`, `reusable_capability`,
`stateful_non_atomic`, `global_version_atomicroot`, `atomicroot`.
Semua mempertahankan schema, identity, operation binding, atomic intent/outbox,
internal envelope single-use, serta receiver dedupe. Shared protections yang
melindungi baseline tidak diatribusikan seluruhnya kepada CAS.

Penambahan tool/typed facts mengubah registry digest. Resolved config lama yang
terikat registry lama ditolak eksplisit dan memerlukan resolution/review baru;
budget/exposure/ledger tidak direset. Receipt lama tanpa `read_binding` perlu
read baru. Global instrumentation berada pada database evaluasi terisolasi.

### Tambahan lintas fase setelah Fase 5

`observability.py`, `run_tests.py`, dan `TESTING.md` menambahkan waktu observasi
UTC, durasi monotonic, profil test, log/JUnit, manifest hash, dan folder hasil
baru per run. Clock protokol untuk expiry/lease/replay tetap terpisah.
Timestamp hook adalah waktu observasi setelah transaksi; deferred hook ditandai,
bukan diklaim sebagai waktu persis linearization SQL. Artifact historis tidak
di-backfill. Ini tambahan observability/testing, bukan hasil historis Fase 4–5.

## 2. Requirement dan bukti file/test

### Fase 4

| Requirement | Source / artifact | Test aktual |
| --- | --- | --- |
| Dependency-ready schedule, exogenous arrival/priority/fault, visible divergence | `atomicroot/sim/scheduler.py`, `sim/scenarios.py`, `phase4_cli.py`, `.runs/testing/timestamps-verification/phase4/paired-contention.json` | `test_phase4_replay.py::test_scheduler_never_selects_unready_and_records_cross_mode_divergence`; `test_paired_contention_has_visible_realized_divergence_and_fresh_fallback` |
| Schema/initial state/resolution/security binding, fresh test keys, exact replay | `sim/replay.py`, `sim/scheduler.py`, `phase4/replay-schema-v1.json` pada folder hasil baru | `test_critical_scenario_exact_replay` untuk 34 skenario; `test_security_fields_are_compared_and_raw_signature_is_retained` |
| Model recorder dan offline binding; egress tetap guarded | `sim/model_tape.py`, `phase4/model-tape.json` pada folder hasil baru | `test_model_tape_exact_binding_failure_and_offline_replay`; `test_model_recorder_is_behind_guarded_egress_and_scope_revocation_blocks_calls` |
| Double ALLOW; mutation contract/policy/delegation/recipient/resource; substitution | Artifact `budget-double-allow`, `exfil-double-allow`, `mutation-*`, `operation-substitution`, `payload-substitution` | Assertions spesifik dalam `test_critical_scenario_exact_replay`; kasus sama lewat koneksi DB kedua pada commit yang dimodelkan |
| Label/content/classifier dan stale/forged approval, replay tiket/grant | Artifact `classification-*`, `approval-*`, `ticket-*`, `worker-admin`; service `approval.py`, `classification.py`, `labels.py` | Parameterisasi replay; `test_ticket_and_grant_concurrent_replay_one_intent_separate_connections` |
| Crash/rollback, lost ack, lease recovery, restart/checkpoint, concurrent A/join/review | Artifact `recovery-*`, `rollback-intent`, `workflow-*`; `framework/outbox.py`, `integration/config_workflow.py` | Parameterisasi replay; `test_checkpoint_reconstruction_rejects_foreign_or_existing_workspace`; regression executor/outbox lama |
| Measured fallback, new snapshot/new ticket, dependency union restart, bounds | `framework/fallback.py`, `framework/contention.py` | `test_measured_stales_trigger_fresh_fallback_no_blocking_hook_inside_gate`; `test_dependency_expansion_releases_reacquires_union_and_has_bound`; `test_dependency_restart_exhaustion_and_cancellation_return_terminal_without_effect` |
| FIFO/cancellation/release, review di luar gate, bounded storm, separate DB connections | `framework/storage.py`, `contention.py`; `docs/phases/scheduler-replay.md` | `test_fifo_admission_timeout_cancellation_release_and_canonical_keys`; `test_fallback_pending_review_does_not_hold_gate_and_grant_stays_fresh`; `test_fallback_escalation_exits_gate_before_human_and_delivery`; `test_contention_storm_terminates_within_attempt_bounds_without_ledger_reset` |
| Writer coverage bersama | Boundary `FrameworkStore.transaction`, admitted inherited APIs; coverage table di `docs/phases/scheduler-replay.md` | `test_all_writer_paths_obey_same_gate_separate_connections` untuk 17 jalur di bawah |

Nama test Fase 4 berada di `atomicroot/tests/test_phase4_replay.py` dan
`atomicroot/tests/test_phase4_fallback.py`.

Coverage exclusion yang diparameterisasi: `gateway`, `authority`, `contract`,
`task_resolution`, `approval`, `scope`, `destination`, `storage`, `label`,
`classification`, `classification_begin`, `classification_result`, `claim`,
`receiver`, `settlement`, `legacy_state`, `initializer`. Executor/inference
memakai transaction boundary yang sama dan diperiksa oleh regression/workflow;
tidak semuanya mempunyai parameter khusus pada test gate tersebut.

Storm test memakai enam runtime/koneksi ke database sama, barrier/events,
attempt bound empat dan restart bound dua. Hasil yang diassert: lima intent
diterima, reservation 1.000.000 dari enam request 200.000 terhadap limit
1.000.000; ledger tidak direset. Ini bounded test, bukan unconditional liveness.

### Fase 5

| Requirement | Source / artifact | Test aktual |
| --- | --- | --- |
| Enam family, fakta concrete, single Z3, composition dan union dependency | `framework/policy_catalog.py`, `framework/dsl.py`, `framework/registry.py`, `framework/runtime.py`, `authority/policy_engine.py`; `examples/phase5/policy-catalog.json` | `test_phase5_policies.py::test_dsl_extension_parameters_composition_and_static_branches`; regression missing facts/solver failures/contract/label/delegation sebelumnya |
| Exfil, budget used+reserved, cap subset dan recipient pinned | Katalog memakai trusted facts/runtime A yang sama; schema menolak cc/bcc/body_ref yang tidak didukung | `test_phase5_modes.py::test_six_modes_paired_ready_schedule_and_semantic_replay` pada exfil/budget/recipient/revocation/classification; `test_schema_and_unsupported_email_fields_apply_to_all_modes` |
| Fresh, missing/forged/unreleased/wrong resource/agent read provenance | `framework/runtime.py`, `operations.py`, `registry.py`, `outbox.py`; `readbasis` immutable | `test_positive_update_provenance_schema_and_atomic_version`; delapan varian `test_missing_forged_or_unreleased_read_is_not_worker_selectable` |
| Stale sebelum authorization DENY; sesudah ALLOW STALE_TICKET; rollback/race | Same write kernel dan Gateway CAS | `test_stale_receipt_before_authorize_and_after_allow_requires_new_read`; `test_write_rollback_and_separate_connection_race`; manifests `stale_before_authorize` dan `stale_write` |
| Sensitive exposure tetap konservatif; executor memakai actual delivered receipt | Guarded adapter dan executor A yang sama | `test_output_cannot_lose_sensitive_shared_exposure`; `test_executor_A_can_use_its_actual_delivered_read_receipt_for_update` |
| Enam mode terisolasi, capability signature/scope/expiry nyata, network aman | `evaluation/modes.py`, `evaluation/runner.py`, `examples/phase5/six-mode-matrix.json` | `test_reusable_capability_signature_subject_scope_expiry_and_reuse`; `test_modes_cannot_expose_unsafe_service_or_provider_network`; `test_actual_executor_A_guarded_wiring_preserves_operation_identity_across_modes` |
| Global writer/approval coverage dan independent key false conflict | Global instrumentation dalam `evaluation/modes.py` | `test_global_instrumentation_covers_other_connections_and_executor_writers`; `test_global_approval_own_consent_transition_and_final_freshness`; scenario `independent` |
| Oracle independen, valid/injected violations, denominator N/A, labels terpisah, no retroactive violation | `evaluation/oracle.py`, actual `_intent_facts`, receiver receipts dan synthetic ground-truth map | Seluruh `test_phase5_oracle.py`, khususnya `test_independently_injected_violation` pada enam family |
| Once/dedupe/recovery/rollback, paired inputs dan exact replay | `evaluation/scenarios.py`, manifests, 78 mode artifacts dan 13 paired reports | Parameterisasi `test_six_modes_paired_ready_schedule_and_semantic_replay`; scenario `once`, `lost_ack`, `rollback`, `contention` |

Nama test policy tanpa prefix file di tabel berada pada
`atomicroot/tests/test_phase5_policies.py`; test mode berada pada
`atomicroot/tests/test_phase5_modes.py`.

Semantik: facts lengkap/konsisten diperiksa dahulu; `facts AND NOT(constraints)`
SAT berarti DENY, UNSAT kandidat ALLOW, UNKNOWN/error/timeout tanpa tiket.
Hard DENY tidak dapat dibuka oleh approval. Demo DSL `research_small_action`
memakai parameter 175 serta `and/not/lt/le` tanpa perubahan compiler.

## 3. Command dan hasil aktual

Jalankan dari root repository memakai venv proyek. Hasil historis terpisah dari
hasil observability terbaru; angka test tidak dijumlahkan sebagai trial independen.

| Run | Command aktual, setelah prefix `.\.venv\Scripts\python.exe` | Hasil |
| --- | --- | --- |
| Fase 4 targeted | `-m pytest atomicroot/tests/test_phase4_replay.py atomicroot/tests/test_phase4_fallback.py -q --junitxml=.runs/phase4/targeted.xml` | 67 passed; 14,330 detik; 0 failure/error/skip |
| Fase 4 regression historis | `-m pytest atomicroot/tests -q --junitxml=.runs/phase4/regression.xml` | 446 passed; 43,957 detik |
| Fase 5 targeted | `-m pytest atomicroot/tests/test_phase5_policies.py atomicroot/tests/test_phase5_modes.py atomicroot/tests/test_phase5_oracle.py -q --junitxml=.runs/phase5/targeted.xml` | 52 passed; 23,695 detik; 0 failure/error/skip |
| Fase 5 regression historis | `-m pytest atomicroot/tests -q --junitxml=.runs/phase5/regression.xml` | 498 passed; 66,129 detik |
| Regression dan artifact terbaru | `run_tests.py all --output .runs/testing/timestamps-verification` | PASSED; 512 passed; pytest 66,349 detik; 35 replay Fase 4 dan 78 replay Fase 5 cocok; wall duration seluruh run 98,702 detik |
| Filter runner | `run_tests.py scenarios --scenario budget --mode stateful_non_atomic --output .runs/testing/timestamps-filter-verification` | Record dan replay PASSED |
| Demo laporan ini | `.runs/phase45-review/demonstrate.py` | Sukses/ditolak pada kedua fase; tiga exact replay cocok; ledger identik sebelum/sesudah rejection |

Runner terbaru benar-benar menjalankan `-m pytest atomicroot/tests -q
--junitxml <folder-run>/regression.xml`, lalu kedua generator dengan `--output`
masing-masing `<folder-run>/phase4` dan `<folder-run>/phase5`. Executable,
argumen absolut, timestamp UTC, exit code, dan log ada pada `plan.json`,
`summary.json`, `progress.jsonl`, dan log per command di folder run tersebut.

35 replay Fase 4 terdiri atas 34 skenario dan satu varian fallback. Fase 5
memakai 13 scenario plans × enam mode. Seluruh 168 oracle events Fase 5 dalam
run terbaru mempunyai source hook bertimestamp; 153 hash file manifest cocok
saat pemeriksaan pada turn sebelumnya. Signature/private key tidak diganti
dengan timestamp sebagai authority. `git diff --check` juga lulus.

Accepted violating intents / accepted intents pada 13 plan terbaru:

| Mode | Numerator / denominator |
| --- | --- |
| `no_guard` | 7 / 18 |
| `stateless_per_action` | 5 / 16 |
| `reusable_capability` | 6 / 17 |
| `stateful_non_atomic` | 4 / 15 |
| `global_version_atomicroot` | 0 / 10 |
| `atomicroot` | 0 / 11 |

Denominator berbeda karena mode dapat DENY atau BLOCKED pada langkah berbeda.
Ini bukan success rate atas trial acak, bukan peringkat keamanan universal,
dan replay bukan sampel independen tambahan. Pelanggaran yang memang diharapkan
pada unsafe baseline adalah hasil eksperimen, bukan assertion test gagal.

**Gagal / terhalang yang diketahui:** percobaan awal test Fase 4 terhalang
sandbox pada socketpair internal asyncio Windows, sebelum mock SDK berjalan.
Rerun dengan izin lingkungan lulus; fixture `no_network` tetap memblokir provider.
Baseline 379 test Fase 4 dilakukan sesudah instrumentation awal, bukan checkout
pre-change yang sama sekali belum disentuh. Seluruh XML final yang diperiksa
menyimpan nol failure/error; arsip bukan riwayat lengkap setiap percobaan edit.

Pada penyusunan demo laporan ini, percobaan pertama gagal dengan
`ValueError: unsupported replay artifact schema`: script memakai writer artifact
Fase 4 untuk artifact Fase 5. Script diperbaiki memakai writer Fase 5 yang sudah
ada, lalu ketiga replay lulus. Ini kesalahan helper pelaporan, bukan bypass
atau kegagalan CAS. Raw hasil sukses ada di `.runs/phase45-review/demo.log`.

**Belum dijalankan dalam Fase 4–5:** provider/model/JEV live validation,
real external effects, real-clock controlled performance benchmark,
adaptive/full attack search, distributed/multiprocess fallback validation,
formal proof, planner B, serta fase lanjutan. Offline fake/replay tidak
dianggap live verification.

## 4. Demonstrasi berhasil dan ditolak

Demonstrasi dijalankan ulang untuk laporan ini memakai harness/protokol yang
sama. `observe` actions hanya membaca ledger pada boundary; bukan writer.
Artifact lengkap menyimpan payload/security fields dan timestamp. Ringkasan
input/output/state ada pada `.runs/phase45-review/demonstrations.json`.

### Fase 4: initial double ALLOW, hanya transfer pertama diterima

Kontrak task `payments-a`: limit **500 satuan integer fixture**, used=0,
reserved=0. Tidak diklaim sebagai rupiah/USD. Dua input:

```json
{"task":"payments-a","agent":"payer-a","operation":"op-first","tool":"transfer_funds","args":{"to":"account-a","amount":300}}
{"task":"payments-a","agent":"payer-b","operation":"op-second","tool":"transfer_funds","args":{"to":"account-b","amount":300}}
```

Kedua authorization menghasilkan `ALLOW` dari basis awal. Scheduler menjalankan
commit pertama sebelum commit kedua; commit kedua memakai koneksi DB terpisah.

| Langkah | Output aktual | State sebelum dan sesudah |
| --- | --- | --- |
| Berhasil: commit `op-first` | `{"status":"COMMITTED","delivery":"PENDING","operation_id":"op-first"}` | reserved 0 versi 0 menjadi 300 versi 1; used tetap 0; satu event intent dan satu outbox PENDING ditambahkan |
| Ditolak: commit tiket `op-second` lama | `{"status":"STALE_TICKET","stale_keys":["reserved:payments-a"]}` | reserved tetap 300 versi 1; used tetap 0; event/outbox tetap satu; seluruh ledger snapshot sebelum/sesudah identik |

Artifact: `.runs/phase45-review/phase4-budget.json`. Exact replay cocok.
Demo Fase 4 ini berhenti pada intent PENDING: tidak mengklaim sudah delivered.
Pada artifact budget Fase 5 yang juga melakukan dispatch, used akhir=300,
reserved=0, satu outbox RELEASED dan saldo receiver simulasi 300.

### Fase 5: guarded write fresh diterima, stale write ditolak

Task `write-a`, peran `writer`; principal sebenarnya di-resolve trusted runtime.
Read `file` versi 1, content `Synthetic initial file`, PUBLIC, telah RELEASED.
Server mengeluarkan `receipt-test-5-00000008` yang mengikat task/agent/resource/
version/digest. Input write untuk kedua run:

```json
{
  "operation_id":"write-op",
  "tool":"update_document",
  "purpose":"research",
  "args":{
    "resource":"file",
    "digest":"sha256:66e5b1e451065758dd185edd1636085b70c21e514d8322491d4a910f5f04be31",
    "content":"Synthetic proposed update",
    "read_receipt":"receipt-test-5-00000008"
  }
}
```

Full request termasuk resolved `task_id`/`agent_id` ada dalam JSON demonstrasi.
Kedua run memperoleh `ALLOW` sebelum ada perubahan owner.

| Run | Output aktual | Perubahan state |
| --- | --- | --- |
| Berhasil, tanpa mutasi perantara | `COMMITTED`, delivery `PENDING`; dispatch lalu `RELEASED` | document content menjadi `Synthetic proposed update`, versi 1 menjadi 2; label versi konten baru UNKNOWN; conflict-key version document 1 menjadi 2 dan label 2 menjadi 3; satu intent/outbox write baru |
| Ditolak, trusted owner mengubah content sesudah ALLOW | `{"status":"STALE_TICKET","stale_keys":["document:file","label:file"]}` | State sudah berisi `Changed by trusted owner`, document versi 2 dan label UNKNOWN. Rejection mempertahankan seluruh ledger persis; tidak ada intent/outbox write. Hanya read-op RELEASED yang ada. |

Reauthorization dengan receipt lama menghasilkan `DENY`, policy
`no_write_after_stale_read`; receipt tidak di-upgrade menjadi versi 2.
Perlu read baru dan operation/request yang sesuai. Mutasi owner adalah
`trusted_fixture`, bukan capability attacker.

Artifacts `.runs/phase45-review/phase5-fresh-write.json` dan
`.runs/phase45-review/phase5-stale-write.json` masing-masing exact replay cocok.

## 5. Asumsi, hardcoded/fixture, dan batas tersisa

- Trusted runtime/Authority/Gateway/Store/Broker/updaters serta identity context
  berperilaku sesuai implementasi. Worker tidak memiliki SQL/admin/signing key
  atau trusted approver rights. Harness memisahkan actor worker, framework,
  fault dan trusted updater; mutasi admin fixture bukan kemampuan attacker.
- Exclusion fallback hanya **satu proses, database/path yang sama**, dengan
  semua writer melalui admission API. Gate exclusive konservatif pada seluruh
  database, termasuk key independen. SQLite WAL tetap satu physical writer;
  bukan distributed lock. Direct SQL administratif/proses lain tidak dianggap
  terkoordinasi. Per-key CAS tetap menghindari false stale pada key independen.
- Bound fallback tidak menjamin hostile scheduler selalu memberi kesempatan.
  Admission timeout tidak mem-preempt solver/OS/SQLite operation yang sedang
  berjalan. Fairness yang diuji adalah FIFO finite waiter/bounded storm.
- 34 scenario Fase 4 dan 13 scenario Fase 5 adalah authored finite fixtures;
  schedule, clock, synthetic content, response, ground truth, names/IDs,
  amounts 300/limit 500 dan fault injection ditentukan harness. Nominal ini
  bukan hasil model menemukan serangan secara mandiri. Default threshold
  fallback adalah config eksplisit, bukan hasil performance tuning empiris.
- Oracle hanya enam invariant finite-prefix yang dimodelkan, bukan full DSL
  evaluator atau infinite-trace/LTL checker. Ground-truth labels adalah
  synthetic annotations; confidence classifier tidak menjamin correctness.
- Stateless/history-unsupported dan approval step yang tidak ready dilaporkan
  eksplisit. Shared uniqueness/outbox/dedupe tetap melindungi baseline; mode
  `no_guard` masih memakai internal envelope untuk shared kernel. Ini bukan
  eksperimen overhead tanpa crypto versus dengan crypto.
- `irreversible_once` berarti satu task-scoped logical operation ID. ID baru
  belum dibuktikan sebagai tindakan baru secara semantik. COMMITTED berarti
  accepted intent; delivery terpisah, lost ack tetap UNKNOWN/reserved sampai
  outcome pasti. Tidak ada exactly-once guarantee untuk provider arbitrer.
- cc/bcc/body_ref, alias/group resolution dan arbitrary shell write tidak
  didukung. Unknown destination ditolak. PUBLIC bukan izin semua tujuan/versi;
  classifier PUBLIC tidak menurunkan authoritative SENSITIVE/UNKNOWN.
- Replay menggunakan key/tiket sementara baru dan membandingkan exact semantic
  bindings; raw valid signature direpresentasikan sebagai verified canonical
  payload proof untuk key uji. Key produksi/RNG tidak diganti. Checkpoint replay
  mempertahankan identity physical path dan menolak workspace asing/sudah ada;
  portability antar mesin/temp-root terbatas. Registry/environment mismatch
  ditolak, bukan dinormalisasi agar tampak sama.
- Timestamp observasi dan file hashes bukan trusted timestamp/attestation.
  UTC tergantung jam host; monotonic counter hanya bermakna pada proses/run
  yang sama. Deferred observation bukan waktu persis commit. Security fields
  tetap dibandingkan; hanya root observational sidecar dikecualikan.
- Nol accepted violation pada mode CAS di fixture yang dieksplorasi bukan
  pembuktian universal safety. Fase 5.5 dan pekerjaan sesudahnya belum dikerjakan
  sebagai bagian laporan ini.

## Indeks bukti utama

- `docs/phases/scheduler-replay.md`: audit, API, security binding dan coverage Fase 4.
- `examples/phase4/test-results.json`: hasil dan command historis Fase 4.
- `examples/phase5/README.md`: semantics/catalog/matrix dan audit perubahan Fase 5.
- `examples/phase5/test-results.json`: hasil dan denominator historis Fase 5.
- `.runs/testing/timestamps-verification/summary.json`: hasil terbaru runner all.
- `.runs/testing/timestamps-verification/phase4/validation.json`: 35 exact replay.
- `.runs/testing/timestamps-verification/phase5/validation.json`: 78 exact replay.
- `.runs/phase45-review/demonstrate.py`: script demo laporan, bukan tool produksi.
- `.runs/phase45-review/demonstrations.json`: full input/output/state dan waktu demo.
- `TESTING.md`: profil runner serta makna timestamp/protocol clock.
