# System B dengan konfigurasi pengguna

Untuk jalur terbaru gunakan `workspace-v2.json`: inventory dan ceilings tidak
memuat task_id, workflow, atau tuple scope per goal. Runtime membentuk katalog
dari registry; model memilih capability bernama dan host mengalokasikan context.
Initial authorization workspace diperlukan sebelum planning; sesudah itu satu
preview bisnis mencakup requirement, plan, policy dan izin baru. Tool yang belum
diimplementasikan tetap NEEDS_CAPABILITY meskipun spesifikasinya disetujui.

```powershell
.\.venv\Scripts\python.exe run_goal.py --environment examples/workspace/workspace-v2.json --goal "Baca notes-a dan buat output result." --output .runs/dynamic-goal --authorize-live
```

Gunakan `--requirements file.json` untuk requirement terstruktur dari pengguna,
dan `--resource-inputs file.json` untuk input owner baru berupa map resource ID
ke record `{resource,content,label,purposes}`. Proposed label/content dari LLM
tidak menjadi authoritative input. Recipient baru dapat diusulkan dalam proposal
dan ditampilkan sebelum persetujuan operator admin.

**Acceptance live belum lulus.** Baca [hasil implementasi dan kegagalan Qwen](../../docs/REPORTS/DYNAMIC_GOAL_IMPLEMENTATION_REPORT.md).
Panduan di bawah mempertahankan jalur format v1 untuk kompatibilitas dan replay.

Jalur ini tidak mengimpor skenario evaluasi, `write_fixture`, atau proposal bisnis
prebuilt. Lingkungan berasal dari JSON pengguna; goal berasal dari CLI. Contoh
`environment.json` bersifat opsional dan tidak pernah dimuat secara implisit.
Runner lama `examples/phase55/live_ollama.py` tetap tersedia untuk eksperimen dan
replay historis. Tidak perlu membuat salinan backup yang menduplikasi implementasi.

## Sekali jalan dengan review interaktif

Edit/salin `environment.json` sesuai resource, izin, model, dan batas penggunaan.
Jangan memberi label PUBLIC pada data privat hanya agar inference berjalan.
UNKNOWN pada provider adalah izin egress eksplisit untuk goal dan context pengguna,
bukan hasil classifier. Provider lokal tetap memerlukan izin tersebut.

```powershell
.\.venv\Scripts\python.exe run_goal.py --environment examples/workspace/environment.json --goal "Baca my-notes lalu buat ringkasan singkat dengan output bernama result." --output .runs/my-independent-goal --authorize-live
```

Perintah ini adalah panduan penggunaan, bukan jaminan keberhasilan model. Direktori
output harus baru. Runner menampilkan tiga keputusan:

1. Persetujuan konfigurasi lingkungan: ketik digest yang ditampilkan setelah
   memeriksa resource, label, destination, scope, budget, dan caps.
2. Persetujuan preview intake/provider melalui Broker. Sebelum persetujuan ini,
   model belum dipanggil. Intake hanya memiliki izin inference untuk context goal.
3. Proposal bisnis hasil LLM: pilih `approve`, `reject`, atau `pause`. Hanya
   `approve` disusul aktivasi kontrak dan guarded execution. Tidak ada auto-approve
   oleh fixture; input terminal merupakan tindakan operator lokal tepercaya.

LLM menentukan agent/peran, scope pilihan, workflow, policy DSL, output, acceptance,
dan asumsi sesuai proposal schema. Context dan batas akses awal disusun host dari
konfigurasi pengguna; host tidak menyusun workflow/policy bisnis pengganti LLM.
CLARIFY, UNSUPPORTED, invalid proposal, dan kegagalan model tetap dilaporkan.

## Format dan recipient

```powershell
.\.venv\Scripts\python.exe atomicroot_cli.py environment-schema
.\.venv\Scripts\python.exe atomicroot_cli.py schema
.\.venv\Scripts\python.exe atomicroot_cli.py environment-preview my-environment.json
```

Environment v1 berisi `task_id`, `purpose`, `resources`, `destinations`, `scope`,
`budget_limit`, `max_agents`, `limits`, `provider`, dan `planning`, serta
`schema_version: 1`. Resource content dibatasi 8192 byte; file konfigurasi 32768 byte.
Context host dibuat otomatis dengan nama berbasis digest konfigurasi, maksimal
16 resource total dan 12 rule scope termasuk context. Batas efektif agent ikut
dibatasi kapasitas resource/rule; tidak semua nilai max_agents cocok untuk setiap
konfigurasi. Semua input diperiksa parser dan resolver, bukan schema JSON saja.

Tidak ada recipient bawaan. Untuk memakai recipient berbeda, deklarasikan di
`destinations` sebagai `kind: recipient`, `endpoint: null`, `models: []`,
`labels: []`, dengan purpose yang sesuai; sertakan tuple izin tool/destination
di `scope`. LLM memilih dari izin tersebut. Recipient yang tidak diizinkan tetap
ditolak; persetujuan proposal bisnis tidak membuat entitlement baru secara diam-diam.
Onboarding recipient yang belum dideklarasikan dari output LLM belum ditambahkan.

Konfigurasi ini adalah batas izin lingkungan, bukan template usecase: tidak
memuat daftar agent, workflow bisnis, policy prebuilt, atau goal yang harus diikuti.
Usecase berbeda dapat memakai format yang sama. Tool/fact/operator baru tetap
memerlukan implementasi adapter/registry tepercaya. Tidak ada shell bebas,
registrasi tool oleh model, atau klaim universal tanpa batas kemampuan.

## CLI bertahap dan resume

```powershell
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace init-environment my-environment.json --accept-digest sha256:DIGEST_DARI_PREVIEW
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace intake-preview
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace decide-intake approve
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace activate-intake
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace --authorize-live plan goal planning my-task --goal "Goal pengguna"
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace preview goal
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace decide goal approve
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace activate goal
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace --authorize-live execute goal
.\.venv\Scripts\python.exe atomicroot_cli.py --directory .runs/my-workspace --authorize-live execute goal --command recover
```

Untuk output `run_goal.py`, session selalu `goal`, intake `planning`, task sesuai
konfigurasi. Resume memakai direktori yang sama melalui CLI bertahap; jangan
menginisialisasi ulang ledger. Existing historical CLI tetap kompatibel: konfigurasi
lama mempertahankan default fake/scripted, dan `--proposal`/`--responses` tetap
memilih driver offline. Workspace baru memakai live sebagai default, selalu
memerlukan `--authorize-live`. Eksekusi/status tidak memberi izin panggilan tanpa
flag tersebut. Paid provider memerlukan pricing dan spend cap eksplisit.

## Artifact dan batas

Output menyimpan environment preview, intake preview, proposal preview, goal
artifact, result, progress JSONL, SQLite ledger/checkpoint, dan signing key lokal.
Preview/result/progress memiliki timestamp UTC. Artifact model memuat respons
aktual serta binding; replay offline tidak menjanjikan provider mengulang output.
Signing key tidak masuk export goal artifact; jangan membagikan seluruh workspace.

Ini prototype operator lokal tepercaya, bukan autentikasi multiuser produksi.
Semua efek bisnis masih simulasi. Bootstrap dan aktivasi intake saat ini memakai
composed transaction: fault setup rollback, termasuk catalog dan resource baru.
Retry hanya berlaku pada workspace yang masih kosong; existing ledger tidak
di-reset. Workspace INSTALLING dari versi historis perlu diperiksa secara
eksplisit sebelum dipakai kembali.

Live Qwen pada runner baru sudah diuji: 10 calls; satu read assisted berhasil,
recovery tanpa call/read tambahan, dan replay planning 6/6 cocok. Goal biasa masih
mengalami intent mismatch atau CLARIFY akibat pemilihan scope yang salah. Lihat
[audit live dan gap](../../docs/REPORTS/PHASE_55_WORKSPACE_LIVE_AUDIT_REPORT.md).
Keberhasilan assisted tidak berarti planning bebas sudah andal. Offline test menjalankan resolver,
Broker, Z3, Gateway, receiver simulasi, dan recovery nyata dengan model fake yang
binding-nya eksplisit. Fixture test tidak menjadi dependency penggunaan normal.
