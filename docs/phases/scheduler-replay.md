# AtomicRoot Fase 4 — Scheduler, replay A, dan fallback

Status: implemented dan offline verified. Effects tetap simulasi. Tidak ada
model/provider live yang divalidasi dalam pekerjaan ini. Pekerjaan berhenti
pada Fase 4; six-mode suite, empat policy benchmark tambahan, full attack search,
planner B, backend/framework baru, dan benchmark penuh tidak dikerjakan.

## Audit fondasi Fase 3–3.7

Audit memakai source, dependency, roadmap A → B, dan regression aktual. Perubahan
Fase 3.7 yang sudah ada pada working tree dipertahankan. Validasi awal terhadap
379 test lama lulus dalam 21,63 detik setelah instrumentation awal ditambahkan.
Percobaan sebelum itu tertahan oleh sandbox pada socketpair internal Windows
asyncio, sebelum mock SDK berjalan. Test tersebut lulus di luar sandbox;
fixture `no_network` tetap memblokir koneksi provider.

| Requirement | Bukti fondasi | Gap dan perubahan Fase 4 |
| --- | --- | --- |
| Snapshot konsisten, Z3 tunggal, concrete footprint, single-use signature, Fresh/CAS | `framework/runtime.py`, `authority/policy_engine.py`, tests fase 1–3 | Dipakai kembali; tidak ada evaluator alternatif atau refresh tiket stale. |
| Approval exact payload dan basis fresh sebelum approve/final commit | `approval.py`, `contracts.py`, `test_phase3_labels_approval.py` | Hook review/decision dan replay basis berubah; grant tetap diperiksa oleh Broker lama. |
| Content/label binding dan classifier konservatif | `labels.py`, `classification.py`, `test_phase35_classifier.py` | Hook committed mutation/acceptance, replay false PUBLIC/error/abstention/restriction/stale. |
| Intent atomik, lost ack, lease recovery, receiver dedupe | `storage.py`, `outbox.py`, `test_phase3_outbox.py` | Hook claim/apply/result; artifact rollback, restart, stale lease dan lost ack. |
| TaskSpec, registry, parent rights, delegasi | `task_spec.py`, `tasks.py`, `test_phase36_tasks.py` | Resolved config/basis disimpan dalam artifact; perubahan limit/policy memakai TaskService/review/activation. |
| Concurrent DAG, shared exposure, review pause, durable stage/checkpoint | `config_workflow.py`, `test_phase37_executor.py` | Replay worker concurrent dengan effect-window plan, restart, join dan review/resume. |
| Scheduler umum dan versioned exact replay | `sim/harness.py` hanya checkpoint Fase 2 | Tambah `ReadyScheduler`, schema v1, trusted replay host, CLI dan examples. Harness lama tetap tersedia. |
| Contention fallback semua writer | GuardedTools sebelumnya hanya retry optimistic | Tambah coordinator bersama per database dan `commit_fresh`; explicit opt-in config. |

Path source di tabel berada di `atomicroot/`; tests berada di `atomicroot/tests/`.
Database schema tidak berubah. Tidak ada dependency tambahan.

### Perubahan pada fondasi fase terdahulu

- Factory tiket menerima clock/ID factory dari host; default ID/nonce memakai
  UUID penuh. Signing RNG produksi tetap terpisah dari TestInputs.
- Service approval, contract, classification, outbox, executor dan inference
  memakai ID factory store yang sama untuk replay; binding dan validasinya tetap
  dilakukan oleh service asal. Authority tetap satu-satunya pembuat tiket.
- FrameworkStore menambahkan admission sebelum writer connection lock, hooks
  setelah commit, dan wrapper untuk inherited writer APIs. Setter mempertahankan
  perbandingan canonical JSON, termasuk membedakan integer `0` dari boolean
  `false`, dan tidak menghilangkan missing-key version transition.
- Executor A menambahkan observasi checkpoint tanpa mengganti planner, schema
  TaskSpec, LangGraph saver, ledger atau aturan completion. Perubahan Fase 3.7
  yang sudah ada sebelum tugas ini tidak diperlakukan sebagai fitur Fase 4 baru.

## Scheduler API dan CLI

`sim/scheduler.py` menyediakan `Action`, `ReadyScheduler`, `TestInputs`,
`HookLog`, `artifact_schema`, load/save dan paired comparison. Action mempunyai
ID, kind, actor, dependencies, logical arrival, priority dan immutable data.
Scheduler hanya memilih action yang dependencies, arrival dan protocol
prerequisites-nya ready. Default memilih prioritas terbesar lalu urutan workload;
preferred/exact plan memilih hanya di antara ready actions. Pilihan unready tidak
dipaksakan: divergence dicatat dan scheduler memilih action ready yang tersedia.
Tanpa action ready atau arrival mendatang, hasilnya `BLOCKED` dengan daftar
action tertahan. DAG/action bound maksimum 2048; tidak ada race berbasis sleep.

```powershell
.\.venv\Scripts\python.exe phase4_cli.py list
.\.venv\Scripts\python.exe phase4_cli.py schema
.\.venv\Scripts\python.exe phase4_cli.py record budget-double-allow .runs/phase4/budget.json
.\.venv\Scripts\python.exe phase4_cli.py replay .runs/phase4/budget.json
.\.venv\Scripts\python.exe phase4_cli.py record fallback-contention .runs/phase4/optimistic.json
.\.venv\Scripts\python.exe phase4_cli.py record fallback-contention .runs/phase4/fallback.json --mode fallback
.\.venv\Scripts\python.exe phase4_cli.py pair .runs/phase4/optimistic.json .runs/phase4/fallback.json
.\.venv\Scripts\python.exe examples/phase4/generate.py
```

`ReplayHost` menerima workload/config A eksplisit melalui API Python. CLI menyediakan
34 finite scenarios; ini kumpulan mekanisme Fase 4, bukan suite benchmark Fase 5.
Generator menulis 35 artifact, schema, contoh model tape, hasil per scenario dan
paired contention. Action `worker` hanya mempunyai guarded worker APIs; upaya
admin ditolak. `trusted_fixture`, `fault` dan `framework` merupakan actor harness
terpisah. Role tersebut tidak pernah menjadi capability worker. Fixture mutasi
key-level diberi audit `TRUSTED_UPDATER_FIXTURE`; bukan serangan worker yang
mempunyai signing key, approver identity, SQL atau admin access.

Hooks lama snapshot/ticket/before-CAS/after-commit dipertahankan. Tambahan mencakup
committed mutations per prefix conflict key, service review/approve/activation,
classification result/acceptance, outbox claim, receiver apply, ack UNKNOWN/result,
checkpoint start/recover/resume/saved, serta boundaries worker/stage/effect A.
Mutation hooks dipublikasikan setelah transaksi sukses. Transaksi gagal tidak
dipresentasikan sebagai partial committed state. Di fallback, seluruh hooks
ditunda sampai exclusion gate dilepas agar observer tidak menunggu writer yang
diblokir gate sendiri. Artifact menandai observasi tersebut dengan `deferred` dan
`observed_after: fallback_release`, termasuk updater arrival yang ikut tertunda.
Penggunaan blocking hook snapshot memerlukan connection
terpisah untuk updater, sebagaimana controlled tests lama; satu connection tidak
dapat menjalankan transaksi lain saat snapshot-nya masih terbuka.

## Binding dan exact replay

Artifact v1 menyimpan TaskSpec, plan, delegasi, resolved artifact/basis, registry
digest, policy definitions/versions, prompt/executor/dependency versions, initial
state/labels/content digests, action/operation IDs, arrivals/priorities/fault plan,
chosen-ready steps, logical clock, terminal ledger, authorizations, reviews,
outbox/receiver observations dan hook trace. Seed bukan schedule.

`TestInputs` menginjeksi clock, ID factory dan RNG scheduler khusus test. Default
runtime tetap memakai UUID entropy dan `SigningKey.generate()`; test RNG tidak
menggantikan crypto RNG. Replay menghasilkan temporary signing key baru dalam
memory, lalu mengeluarkan tiket baru melalui Authority/Z3/Gateway yang sama.
Private key tidak ditulis ke artifact atau file.

Raw signed tickets tetap disimpan. Semantic comparison mempertahankan identity,
operation, exact payload hash, ticket ID, nonce, expiry, footprint/version dan
write set secara verbatim. Hanya bytes signature dari key sementara yang berbeda
direpresentasikan sebagai proof Ed25519 valid beserta digest canonical signed
payload dan role key. Invalid signature tetap dibandingkan verbatim. Tidak ada
penghapusan field keamanan atau pembaruan versi tiket demi menyamakan trace.

Binding physical checkpoint directory dipertahankan, termasuk config digest dan
operation IDs turunannya. Replay merekonstruksi direktori temporary dengan
identity path yang sama, dalam keadaan kosong. Target wajib langsung di trusted
temporary root dengan nama harness yang valid, belum ada, dan bukan symlink.
File yang sudah ada tidak dihapus. Ini membatasi portability exact checkpoint
replay antar mesin/temp-root; environment/path divergence ditolak secara jelas.
Replay tanpa checkpoint memakai direktori temporary baru; tidak terikat TEMP
root pembuat artifact karena tidak mempunyai checkpoint path dalam binding.

Untuk A concurrent, dua root worker benar-benar rendezvous pada barrier. Effect
window dipilih dari node yang sudah ready melalui `effect_order` eksplisit;
join tetap memakai dependency executor. Pilihan dan ready set disimpan sebagai
`effect_schedule`. Raw observer hooks juga disimpan; urutan kedatangan observer
independen bukan field yang dinormalisasi menjadi keputusan authorization.
Semantic trace membandingkan pilihan, protocol outputs dan seluruh state/intent
yang teramati, bukan latency thread atau ID internal LangGraph yang tidak
menjadi authority. Tidak ada perbandingan final trace identik lintas guard.

Pairing memerlukan workload/arrival/priority/fault plan identik. Masing-masing
mode menyimpan realized schedule, blocked actions, observation differences dan
divergence. Pada contoh contention, tiga kedatangan updater tepercaya sama-sama
direkam. Optimistic menghabiskan retry; fallback menerima intent setelah dua
stale terukur dan update ketiga baru berjalan setelah exclusion dilepas.
Update setelah commit yang sah bukan stale-authorization violation.

## Model recorder/replay

`sim/model_tape.py:ModelTape` membungkus model provider yang dipilih host. Tempatkan
di `ModelBridge` agar panggilan delegate tetap hanya terjadi setelah guarded
egress commit. Test mengonfirmasi scope revocation membuat nol tambahan call.
ModelTape sendiri bukan otorisasi egress atau jalur bypass Gateway.

Key rekaman mengikat provider/model, tape schema, prompt version, exact messages,
context digest, response schema/digest, dan ordinal panggilan untuk context sama.
Respons dan digest-nya direkam; exception hanya menyimpan jenis error. Replay
tanpa delegate tidak memanggil network dan menolak binding yang berbeda. Dua
call identik dapat mempunyai dua respons berbeda; recorder bukan receiver dedupe
atau inference billing memo. Call/token/retry caps tetap ditangani InferenceMemo.
Live respons dapat direkam melalui delegate yang sudah diotorisasi dan kemudian
diputar offline. Tidak ada klaim provider live akan mengulang output identik.
Contoh `model-tape.json` berasal dari fake provider, bukan live validation.

## Fallback dan exclusion coverage

Default runtime/GuardedTools tetap optimistic. Aktifkan lewat trusted composition
root `FrameworkRuntime(..., fallback=FallbackConfig(...))`, atau pakai
`commit_fresh` langsung. CLI Fase 4 memakai `--mode fallback`. Threshold default
dua `STALE_TICKET` terukur per exact operation/request; tidak memakai dugaan
benign worker. Maksimum empat authorization attempts, dua dependency restarts,
dan lima detik admission budget. Config memvalidasi integer/bounds.

Semua instance yang menunjuk resolved path database sama dalam satu proses
berbagi coordinator. Setiap writer mengambil shared admission sebelum connection
lock dan `BEGIN IMMEDIATE`. Fallback mengambil FIFO exclusive admission dan
concrete-key reservations dalam canonical lexical order. Untuk implementasi
sederhana ini, exclusion bersifat konservatif pada **seluruh database**, termasuk
writer dengan key independen. Key independen tetap tidak saling men-stale pada
CAS; ini bukan klaim concurrency physical writes atau lock distributed.

Setelah gate didapat, Authority membaca snapshot baru dan mengevaluasi exact
request/op lagi dengan Z3. Tiket baru memakai protokol normal. Dependency/write
set baru yang tidak tercakup menyebabkan release dan reacquire union, dengan
restart bound. Tiket yang dibuat saat ekspansi tidak pernah dipakai untuk commit.
Commit tetap memakai CAS, signature, replay dan fresh grant checks yang sama.

| Writer | Boundary bersama | Test coverage |
| --- | --- | --- |
| Optimistic Gateway dan fallback Gateway | `FrameworkStore.transaction` | `gateway`, stale/fallback/concurrent replay tests |
| Scope/delegation/contract/policy activation | transaction pada TaskService/ContractService | `contract`, `scope`, replay revision limit/policy-set |
| Catalog recipient/provider dan entitlement | transaction pada TrustedCatalog | `destination`, `scope` |
| Owner storage/content dan Label Manager | transaction | `storage`, `label` |
| Classification begin/result/acceptance dan exposure propagation | transaction | `classification`, false PUBLIC/stale/restriction artifacts |
| Broker review/grant/consumption | transaction | `approval`, replay/concurrent grant tests |
| Outbox claim/receiver apply/settlement | transaction | `settlement`, claim/lease/lost-ack artifacts dan tests lama |
| Trusted `set_state`, initializers dan inherited state APIs | coordinator admission + transaction/admitted inherited API | `legacy_state`, `initializer`, typed state regression |
| Executor actions/output/history dan inference memo writes | transaction | regression executor/memo dan checkpoint artifacts |

`test_all_writer_paths_obey_same_gate_separate_connections` menahan exclusive
gate, memastikan writer dari connection lain benar-benar masuk antrean, lalu
membuktikan writer selesai setelah release. Direct administrative SQL, writer
dari proses lain, dan konstruktor schema sebelum runtime aktif tidak merupakan
supported exclusion protocol. Seluruh application policy writers dalam supported
scope harus memakai database yang sama dan API store tersebut. CAS tetap wajib;
lock tidak dijadikan otoritas pengganti freshness.

FIFO admission mencegah writer baru mendahului waiter yang sudah antre. Cancellation
diperiksa sebelum attempt/admission dan selama wait; queued cancellation/timeout
menghapus waiter. Setiap exit/exception melepas gate/reservations. Setelah attempt
dimulai, langkah local solver/SQLite tidak di-interrupt secara parsial; commit
yang sudah linearized tidak dibatalkan oleh cancellation berikutnya. Admission
budget bukan hard deadline preemptif untuk solver atau OS/SQLite scheduling;
solver dan SQLite memiliki bound sendiri. Human review, network/inference dan
delivery berada di luar gate dan transaksi. ESCALATE keluar critical section;
grant tetap diperiksa fresh pada approve dan final commit.

Terminal reasons mencakup `AUTHORIZATION_TERMINAL`, `RETRY_EXHAUSTED`,
`DEPENDENCY_RESTART_EXHAUSTED`, `CONTENTION_TIMEOUT`, dan `CANCELLED`; decision
atau rejection konkret tetap tersedia. Pending ambiguous delivery tidak melepas
reservation. Bounded fairness/termination berlaku pada finite harness dan waiter
yang dijadwalkan, bukan unconditional liveness di hostile scheduler.

## Commands dan bukti

```powershell
.\.venv\Scripts\python.exe -m pytest atomicroot/tests/test_phase4_replay.py atomicroot/tests/test_phase4_fallback.py -q --junitxml=.runs/phase4/targeted.xml
.\.venv\Scripts\python.exe -m pytest atomicroot/tests -q --junitxml=.runs/phase4/regression.xml
.\.venv\Scripts\python.exe examples/phase4/generate.py
git diff --check
```

Hasil final dicatat di `examples/phase4/validation.json` dan
`examples/phase4/test-results.json`. XML/log mentah berada di `.runs/phase4/`.
Final regression: **446 passed**, termasuk **67 test Fase 4**, tanpa failure,
error atau skip. Generator memverifikasi **35 exact replay** atas **34 skenario**
dan varian fallback contention. CLI record/replay/schema/pair dan
`git diff --check` berhasil. Hasil pair memang berbeda pada contention; tidak
disamakan secara paksa. Validation live berstatus **NOT RUN**.
Tidak ada perubahan pada empat benchmark policy tambahan atau fase setelahnya.
Tidak ada pembuktian formal, universal safety guarantee, distributed liveness,
atau exactly-once provider delivery yang disimpulkan dari hasil offline ini.
