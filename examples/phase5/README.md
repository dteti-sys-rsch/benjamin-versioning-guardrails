# AtomicRoot Fase 5 — Katalog, enam mode, dan oracle

Lingkup: finite mechanism fixtures dengan effects simulasi. Fase 5 berhenti
sebelum Fase 5.5. Tidak ada full benchmark/adaptive search, planner B, provider
atau framework baru, external effect nyata, formal proof, atau penulisan paper.
Z3 tetap satu-satunya evaluator policy aktif.

## Audit fondasi dan perubahan minimum

Baseline aktual: **446 test lulus**. Source README, dependency, registry,
compiler, runtime, TaskSpec/delegasi, executor, scheduler/replay, fallback, outbox
dan tests lama dibaca sebelum perubahan. Working tree Fase 3.7–4 dipertahankan.

| Requirement | Bukti yang sudah tersedia | Gap / perubahan Fase 5 |
| --- | --- | --- |
| Exposure sebelum read tersedia dan classifier konservatif | `labels.py`, `classification.py`, `runtime.py`; tests Fase 3–3.7 | Dipakai kembali; katalog membedakan official/candidate/effective/ground truth. |
| Used/reserved/settlement, single-use dan stable operation | `runtime.py`, `outbox.py`; race, rollback, lost-ack dan restart tests | Dipakai kembali; family `irreversible_once` kini juga mempunyai constraint typed AST eksplisit. Shared DB uniqueness tetap melindungi seluruh baseline. |
| Capabilities dan pinned recipient | `tasks.py:scope_expression/delegation_constraints`, registry dan TaskSpec | Family katalog memetakan enforcement yang sama, tidak membuat capability system kedua di service utama. |
| Read-before-write | Registry belum mempunyai guarded content write | Tambah `update_document`, immutable server read binding, typed receipt facts dan atomic content/version transition. |
| Six-mode comparison | Baseline Fase 1–2 belum meliputi konfigurasi A/outbox | Tambah subclass evaluasi terisolasi; shared request schema, core Gateway, GuardedTools, outbox dan simulator dipakai semua mode. |
| Composition evidence | ALLOW ticket sudah memakai union dependency | DENY response sebelumnya memakai footprint policy terpilih sebelum policy lain dibaca. Perbaiki response menjadi union penuh; enforcement ALLOW tidak diganti. |
| Independent oracle / replay | Fase 4 scheduler, test signing keys, paired inputs dan replay tersedia | Reuse scheduler/host; tambah independent finite-prefix invariant monitor, semantic intent facts dan mode artifacts. |

Source pada tabel berada di `atomicroot/framework/`, kecuali evaluator di
`authority/`, executor di `integration/`, dan harness di `evaluation/`/`sim/`.
Tidak ada dependency atau backend baru. SQLite WAL dan satu physical writer
tetap berlaku. Core DB memakai tabel yang sama; read provenance menambah
versioned `readbasis:{task}:{operation}` rows. Global evaluation DB memasang
instrumentation triggers, bukan migrasi ke main service.

## Enam family benchmark pada satu AST/Z3

Katalog lengkap dan fact metadata di `examples/phase5/policy-catalog.json`.
`framework/policy_catalog.py` menghubungkan family ke constraint yang benar-benar
dipakai runtime. Cap/recipient memakai typed AST builder Fase 3.6 yang sama,
bukan evaluator atau capability registry baru. Custom JSON DSL melalui
`compile_policy` menghasilkan node yang sama, memakai `ast_type`, semua-cabang
`dependencies`, `StatusReader`, dan `solve` yang sama.

| Family / applicability | Semantik dan concrete keys | Authority / transisi | Evidence dan batas |
| --- | --- | --- | --- |
| `no_exfil_after_sensitive`, external business release | Conservative task/shared exposure; label resmi, accepted restriction dan resource binding. Keys exposure, contract, label, document serta scope provider yang berlaku. | Gateway menambah exposure dalam commit sebelum read result; Label Manager menginvalidasi dependency ketika label/restriction menguat. | Read events, label/proposal terpisah dan immutable release. UNKNOWN mengikuti DENY/ESCALATE. Klaim model tidak menghapus taint. Provider exception lama tetap memerlukan egress authorization. |
| `budget_monotone`, spending | `used + reserved + amount <= approved limit`, integer nonnegative/bounded. Keys budget/reserved/contract. | Gateway reserve; Dispatcher settle tepat sekali terhadap durable receipt. Unknown delivery tetap reserved. | Intent facts dan receiver receipts; settlement tidak menggandakan used. Tidak mengklaim exactly-once provider billing. |
| `cap_subset`, managed A | Correlated agent relation subset task relation subset parent entitlement; membership/revocation nyata. Keys delegation, agents, entitlement, taskresolved/taskmode, contract dan catalog destination. | TaskService/ContractService/TrustedCatalog, aktivasi/revisi/revocation yang sah. | Resolved config dan tuple tool/resource/destination/purpose/amount. Tidak mengganti relation dengan Cartesian product allowlists. |
| `recipient_pinned`, external tool | Exact concrete catalog ID dan per-agent relation. Keys contract/destination/delegation/entitlement. | Trusted catalog dan reviewed config; freeze `args.to` sebelum authorize. | Signed payload hash, outbox dan applied destination identik. cc/bcc/body_ref ditolak di semua mode. Tidak ada alias/group resolver; case/alias lain tidak dianggap nama terdaftar. RFC email normalization bukan fitur prototype ini. |
| `no_write_after_stale_read`, `update_document` | Read receipt task/agent/resource/version/digest harus sesuai current document dan requested base digest. Keys readbasis, document, label, contract dan delegation. | Trusted read receiver mencatat proof; Authority mengikat readbasis immutable; Gateway melakukan write/version/label update atomik. | Missing/forged/unreleased/wrong-task/agent/resource proof tidak memberi tiket. Stale sebelum authorize DENY; setelah ALLOW menghasilkan STALE_TICKET di main CAS. |
| `irreversible_once`, task/logical operation ID | `NOT(operation_committed)` dalam AST, stable digest/identity, unique intent dan atomic ticket/nonce consumption. Keys operation/consent; DB task-operation uniqueness. | Gateway false → true; Broker consumes grant bila berlaku. | Status reread bukan intent baru; receiver dedupe adalah mekanisme lain. ID baru tidak membuktikan action baru secara semantik. Ini finite-prefix, bukan LTL/infinite-trace checker. |

Semua applicable policies dievaluasi dari snapshot konkret yang sama; footprint
menggabungkan static semua cabang dan dynamic trusted reads, termasuk policy-set
membership. Query setiap constraint memakai `facts AND NOT(constraint)`; semua
constraint wajib lolos, setara dengan menolak pelanggaran salah satu constraint
dalam `facts AND NOT(all applicable constraints)`. SAT berarti DENY; UNSAT hanya
kandidat ALLOW setelah prerequisites sah. Konsistensi facts diperiksa lebih dulu;
missing, malformed, kontradiksi, timeout, UNKNOWN/error tidak menghasilkan tiket.
Hard DENY mengalahkan ESCALATE. Approval tidak membuka solver/schema failure.

`research_small_action` di katalog adalah demo JSON DSL tambahan dengan parameter
175 dan komposisi `and/not/lt/le` atas registered facts. Tests mengubah parameter
dan menguji boundary/composition tanpa edit compiler. Ini bukan benchmark family
wajib ketujuh atau mode guard ketujuh.

## Guarded write dan receipt

Request baru: `update_document` dengan exact args
`{resource, digest, content, read_receipt}`. Content adalah string maksimal 8192
UTF-8 bytes; string kosong sah. `read_receipt` adalah ID proof server, bukan
dict worker atau field `reads` yang dapat dikosongkan. Request/generation schema,
registry, GuardedTools dan executor A memakai definisi yang sama. Internal
receipt acceptance mempunyai destination null; external destinations tetap
harus terdaftar dan cocok scope.

Read receiver menambahkan `read_binding` yang memuat task, agent, logical read
operation, resource, version dan digest. Authority mencari durable receiver proof
yang sama dengan outbox RELEASED milik caller. Proof yang baru tersimpan namun
belum disettle tidak cukup. Receipt lama tanpa binding Fase 5 memerlukan read
baru; tidak di-upgrade atau diperbarui secara diam-diam.

Registrasi write menyimpan readbasis immutable dalam transaction yang sama
dengan operation registration. Snapshot authorization membandingkan typed read
version/digest dengan current storage lewat Z3. Reauthorization operation/payload
yang sama tidak mengganti receipt/version. Worker yang mengganti base digest
namun mempertahankan receipt lama tetap ditolak. Untuk managed A, source pin yang
berubah juga memerlukan reviewed plan/resolution baru sebagaimana Fase 3.6.

Titik linearization write adalah accepted intent: document, label, version,
ticket/grant consume, event dan outbox berubah dalam satu transaction CAS.
Dispatcher kemudian mensimulasikan applied effect dari frozen `resource_update`;
tidak membaca ulang resource mutable dan tidak menulis ledger dua kali.
Rollback meninggalkan nol partial write/dispatchable effect. Output tidak
mendapat PUBLIC label dari label byte versi lama; sensitive shared exposure
menambah conservative resource restriction yang tidak dapat dihapus classifier
PUBLIC atau generic label update pada versi tersebut.

## Enam mode dan shared protection

Matrix mesin ada di `examples/phase5/six-mode-matrix.json`.

| Mode | Policy/history | Subject/scope/signature | Freshness | Approval/fallback |
| --- | --- | --- | --- | --- |
| no_guard | Tidak ada policy authorization. Instrumentation, schema, host identity, operation ledger dan adapter provenance tetap. | Tidak ada business scope check pada action; signed internal mechanism envelope tetap dipakai shared kernel. | Tanpa CAS. | Tidak mengklaim approval atas policy yang dihilangkan; fallback N/A. |
| stateless_per_action | Request/scope/static amount dan custom non-history constraints. Cumulative budget/exposure/read freshness unsupported/partial, ditampilkan. | Current Phase 3.6 relations dan signed mechanism envelope. | Tanpa state-version acceptance. | Shared Broker bila ada supported escalation; fallback N/A. |
| reusable_capability | Frozen signed scope relation dan static amount; tidak mengikat state version. | Grant subject/task/scope/expiry benar-benar diverifikasi dan dapat dipakai beberapa logical operations. Child mechanism ticket tidak hidup melewati grant expiry. | Tanpa CAS/revocation freshness. | Tidak mengklaim history approvals; fallback N/A. |
| stateful_non_atomic | Snapshot history konsisten, applicable Z3 sama dengan main. | Identity/payload/signature dan ticket single-use shared. | Acceptance tidak memeriksa version CAS dan tidak melakukan atomic reevaluation. | Grant checks/Broker shared tetap sah; fallback N/A. |
| global_version_atomicroot | Policy/history/approval/outbox sama dengan main. | Binding/signature yang sama. Per-key footprint tetap disimpan untuk evidence. | CAS memakai satu global policy version. | Global dependency masuk basis review; bounded fresh fallback Fase 4. |
| atomicroot | Seluruh applicable policy pada snapshot. | Main Phase 3.6 enforcement dan signed exact payload. | Static+dynamic concrete per-key footprint CAS. | Main Broker/outbox/fallback Fase 4. |

Semua mode mempertahankan request schema, trusted caller identity, immutable
operation registration, internal ticket/nonce single-use, outbox uniqueness,
atomic acceptance transaction dan simulated receiver dedupe. Reusable grant
sendiri tidak single-use; internal per-action envelope berbeda dari grant itu.
Invariant read-receipt validity dalam adapter juga shared; baseline tidak diberi
SQL atau cara membuat receipt palsu. Shared protections ini memang dapat
melindungi baseline, terutama `irreversible_once`/recovery/rollback. Hasilnya tidak
diatribusikan seluruhnya kepada CAS. Perbandingan ini bukan overhead benchmark
no-crypto versus crypto karena internal instrumentation signature tetap sama.

`EvaluationAuthority` melaporkan omitted custom rules dan history partial pada
response mode lemah. Schema/config tetap diproses TaskService yang sama sebelum
mode dipilih; no_guard bukan bypass trusted configuration activation. Reusable
grant hanya implementasi baseline terisolasi, bukan capability system baru di
main service. Grant awal yang sama dipertahankan lintas connections/restart;
restart tidak memperbarui expiry atau scope secara diam-diam.

Unsafe modes hanya dibuat `EvaluationAdapter` dalam temporary database fixture.
Main `FrameworkRuntime` tidak mempunyai parameter/request untuk memilih mode.
HTTP composition menolak runtime evaluasi. Semua evaluation authorities menolak
model/classifier provider egress; unsafe mode tidak dapat membuka jalur network.
Scripted/fake/replay input dipakai untuk mekanisme. Tests menjalankan
ConfigWorkflow/GuardedTools yang sama pada enam mode dan membuktikan logical
operation IDs/payload digests tetap sama, serta menguji write memakai receipt
nyata dari ancestor node. Replay mechanism memakai explicit protocol boundaries
dari TaskSpec/plan; opaque model-driven graph replay bukan klaim suite ini.

## Global version dan review

Semua isolated mode databases memasang instrumentation global yang sama;
hanya global mode memakainya untuk freshness. SQLite triggers mencakup setiap
insert/update/delete conflict key, termasuk writer dari connection lain dan
inherited store methods. Hooks constructor mendaftarkan triggers untuk staged
execution actions, outputs, run config/binding dan inference job bindings.
Status/history/checkpoint bookkeeping yang bukan policy fact tidak diikutkan.
Ticket metadata insertion tidak menaikkan policy clock, supaya issue ticket
tidak membuat dirinya stale. Known operation arrivals diinisialisasi sebelum
paired authorization wave pada semua mode; bukan mengubah workload global saja.

Basis review global memeriksa global clock juga. Saat approval operation yang
fresh menulis consent-nya sendiri, GlobalBroker mengikat kembali hanya transisi
infrastruktur itu dalam transaction yang sama. Tidak ada business writer yang
dapat menyela, dan tidak ada pengangkutan approval ke business state baru.
Perubahan relevan sebelum approve atau sesudah approve tetap menuntut review
baru. Final commit memeriksa grant dan CAS seperti main.

Fallback menggunakan coordinator satu proses/database Fase 4; global key ikut
dependency dan canonical reservations. Semua policy writer menaati protocol
yang sama. Gate konservatif pada seluruh database, SQLite tetap satu physical
writer; bukan distributed lock atau unconditional liveness. Scenario contention
membuktikan global dan per-key fallback memakai dua stale terukur dan fresh
authorization; updater arrival tertunda ditandai sebagai deferred sampai release.

## Oracle, pairing dan hasil yang dapat dinyatakan

`evaluation/oracle.py` hanya memonitor enam invariant skenario dari concrete
facts dan semantic events, bukan mengeksekusi JSON DSL atau membaca guard
decision/witness. Gateway mencatat actual `intent_facts` dalam transaction
acceptance sebelum state berubah, terpisah dari snapshot/plan authorization.
Document evidence hanya identity/version/digest, bukan private read bytes.
Oracle menggabungkannya dengan contract/scope timeline, ground-truth content
fixtures, readbasis serta durable receiver receipts. Tests inject violations
langsung ke oracle tanpa menjalankan guard dan memeriksa keenam family.

Accepted violating intents, unique delivered violating effects, protocol API
attempts, attempted logical operations, terminal UNKNOWN dan observed lost ack
dicatat terpisah. Rate menyimpan numerator/denominator; denominator nol →
null dengan label N/A. Applied receipt tetap dapat diketahui oracle ketika
caller kehilangan ack. Candidate/effective labels tidak menjadi ground truth.
Leak terhadap ground truth dilaporkan terpisah dari formal policy violations;
ground truth yang tidak tersedia tetap UNKNOWN. Policy/label yang berubah
sesudah commit sah tidak membuat accepted basis lama retroactively stale.
Ground-truth exposure release adalah metrik konservatif; field terpisah
`ground_truth_byte_disclosures` mengonfirmasi bahwa applied body mempunyai digest
yang sama dengan sensitive source fixture. Copy payload synthetic ini sudah
ditentukan dalam paired workload, bukan bukti bahwa model live mempelajari
rahasia. Duplicate intent tidak otomatis dihitung sebagai duplicate delivery;
receiver dedupe dengan receipt yang sama tetap diakui. Receipt berbeda untuk
efek kedua, atau recipient receiver yang berbeda dari accepted payload, diuji
sebagai delivered violation secara independen.

Manifest sama di enam mode: TaskSpec, plan, identities, operations, immutable
sources, arrivals, priorities dan faults. Realized ready schedule, blocked
actions dan divergence masing-masing mode disimpan. Tidak ada action unready
yang dipaksakan. Approval policy yang dihilangkan baseline bisa menyebabkan
review step tidak ready; itu dilaporkan, bukan mengarang grant. Exfil/budget
canonical membuktikan initial double ALLOW, stale acceptance non-atomic, dan
CAS rejection main/global. Independent tasks menunjukkan false conflict global
sementara per-key berhasil. Once/rollback/lost-ack yang aman di baseline tetap
ditampilkan. Tidak ada universal guarantee dari finite fixtures ini.

## Command, artifact dan kompatibilitas

```powershell
.\.venv\Scripts\python.exe phase5_cli.py catalog
.\.venv\Scripts\python.exe phase5_cli.py matrix
.\.venv\Scripts\python.exe phase5_cli.py schema
.\.venv\Scripts\python.exe phase5_cli.py compare budget .runs/phase5/budget
.\.venv\Scripts\python.exe phase5_cli.py replay .runs/phase5/budget/stateful_non_atomic.json
.\.venv\Scripts\python.exe phase5_cli.py record stale_write .runs/phase5/write.json --mode atomicroot
.\.venv\Scripts\python.exe examples/phase5/generate.py
.\.venv\Scripts\python.exe -m pytest atomicroot/tests/test_phase5_policies.py atomicroot/tests/test_phase5_modes.py atomicroot/tests/test_phase5_oracle.py -q --junitxml=.runs/phase5/targeted.xml
.\.venv\Scripts\python.exe -m pytest atomicroot/tests -q --junitxml=.runs/phase5/regression.xml
git diff --check
```

`examples/phase5/` berisi versioned policy catalog/facts, matrix, 13 manifests,
78 mode artifacts dan paired reports, evaluation schema v1 yang mereferensikan
TaskSpec/request/AST schema yang sama, validation serta actual test results.
Replay mengeluarkan key/tiket baru dari protocol yang sama. Private key tidak
disimpan. Raw signatures, subject/payload/nonce/expiry/versions/read provenance
dipertahankan; semantic comparison hanya merepresentasikan signature key uji
yang direkonstruksi sebagai verified canonical-payload binding. Signature palsu
tidak dinormalisasi menjadi valid. Actual provider responses bukan klaim dapat
diulang identik oleh provider; suite ini tidak memanggil provider.

Registry/request schema berubah karena tool dan typed facts baru. Resolved
config/artifact lama yang mengikat digest registry lama gagal secara eksplisit;
gunakan trusted resolution/preview/review baru, tanpa reset budget/exposure atau
ledger. Historical Fase 4 artifacts tetap bukti historis, bukan diam-diam ditulis
ulang seolah memakai registry baru. Receipt lama tanpa `read_binding` memerlukan
read baru. Live validation berstatus NOT RUN. Hasil final dan raw XML commands
dirujuk oleh `examples/phase5/test-results.json`; tidak ada klaim formal proof.

## Hasil verifikasi aktual

- Baseline: **446 passed**; regression akhir: **498 passed**, termasuk **52 test
  Fase 5**, tanpa failure/error/skip.
- **13 finite scenario plans × enam mode = 78 records**, masing-masing cocok
  dengan exact offline replay. Replay deterministik ini bukan independent trials.
- Pada exfil/budget canonical, empat mode lemah menerima dan menerapkan satu
  intent yang melanggar; per-key/global menolak stale ticket. Kedua mode CAS
  tidak mempunyai accepted violation dalam fixture yang dieksplorasi ini.
- CLI catalog/matrix/schema/record/compare/replay dan `git diff --check` berhasil.
  XML mentah, actual commands dan numerator/denominator ada di test-results.
- Live/provider validation: **NOT RUN**. Semua effect simulasi. Fase 5.5 tidak
  dikerjakan; hasil ini bukan full benchmark atau universal safety guarantee.
