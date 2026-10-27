# Testing AtomicRoot sekali jalan

Gunakan sekarang untuk verifikasi Fase 1–5. Runner ini tidak menjalankan Fase
5.5, benchmark/adaptive search baru, atau provider/effects live. Python dipakai
agar alur yang sama berjalan dari PowerShell maupun Bash, tanpa dependency baru.
Jalankan dari root repository memakai interpreter venv proyek.

```powershell
# Windows / PowerShell
.\.venv\Scripts\python.exe run_tests.py all
```

```bash
# Linux/macOS / Bash
./.venv/bin/python run_tests.py all
```

Runner memakai interpreter yang memanggilnya dan child process dengan argumen
terstruktur, bukan shell command dari worker. Tidak perlu mengaktifkan venv bila
path interpreter dipakai langsung. Setup dependency tetap mengikuti README.

## Pilihan jenis testing

| Profil | Yang dijalankan |
| --- | --- |
| `quick` (default) | Tests timestamp/runner, policy dan oracle; cocok setelah edit kecil. |
| `phase4` | Tests scheduler/replay/fallback dan timestamp. |
| `phase5` | Tests policy, six-mode adapter, oracle, dan timestamp. |
| `regression` | Seluruh `atomicroot/tests`, termasuk fondasi/executor A. |
| `scenarios` | 13 scenario plans × enam mode dan exact offline replay, dengan artifact. |
| `all` | Seluruh regression, generator/replay Fase 4, lalu generator/replay Fase 5. |

```powershell
.\.venv\Scripts\python.exe run_tests.py quick
.\.venv\Scripts\python.exe run_tests.py phase4
.\.venv\Scripts\python.exe run_tests.py phase5
.\.venv\Scripts\python.exe run_tests.py regression
.\.venv\Scripts\python.exe run_tests.py scenarios

# Satu skenario, semua mode dan replay tiap mode
.\.venv\Scripts\python.exe run_tests.py scenarios --scenario budget

# Satu skenario dan mode
.\.venv\Scripts\python.exe run_tests.py scenarios --scenario stale_write --mode atomicroot

.\.venv\Scripts\python.exe run_tests.py --help
```

Daftar nama scenario/mode tersedia lewat `phase5_cli.py list`. `--scenario` dan
`--mode` hanya untuk profil `scenarios`; `--mode` memerlukan `--scenario`.
Profil `all` benar-benar menjalankan semua pilihan yang dicantumkan pada tabel.
Runtime evaluasi tetap terisolasi dengan fixture synthetic/simulator.

## Folder hasil dan status

Default setiap eksekusi membuat folder baru:

```text
.runs/testing/<UTC-date-time>-<unique-id>/
    plan.json             # actual executable, args, dependencies dan waktu
    progress.jsonl        # command start/heartbeat/finish dalam UTC
    summary.json          # status run, actual exit codes, durasi dan JUnit counts
    files.json            # relative paths, sizes, modified UTC dan SHA-256
    regression.xml        # atau quick.xml / phase4.xml / phase5.xml
    regression.log        # raw stdout/stderr; tiap command punya log sendiri
    phase4/               # hanya profil all
    phase5/               # profil all/scenarios tanpa filter
```

Untuk scenario terpilih, artifact berada di subfolder nama scenario. Replay
mempunyai log/status sendiri. `--output <folder-baru>` memilih lokasi eksplisit;
folder yang sudah ada ditolak agar bukti lama tidak tertimpa. Generator asli
juga mendukung `--output`, misalnya:

```powershell
.\.venv\Scripts\python.exe examples/phase5/generate.py --output .runs/my-new-evidence
```

Runner otomatis mengarahkan generator ke folder run baru, sehingga tidak
menimpa `examples/phase4` atau `examples/phase5`. Generator yang dipanggil
langsung tanpa `--output` tetap menulis ke folder contoh seperti sebelumnya.
Historical `test-results.json` tetap laporan historis; hasil baru ada dalam
`summary.json` dan JUnit baru, dengan actual commands pada `plan.json`.

Kode keluar runner: 0 bila seluruh command lulus, 1 bila ada kegagalan/timeout,
130 bila di-interrupt. Timeout default 300 detik per command dan dapat diatur
dengan `--timeout`, maksimum 3600 detik. Command independen berikutnya tetap
dijalankan ketika sebuah command gagal; replay yang bergantung pada record
gagal diberi SKIPPED, bukan dipaksakan. Ctrl+C menghentikan child aktif dan
menyimpan status interruption. Hasil/log parsial dipertahankan.

Pelanggaran yang sengaja ditunjukkan mode lemah pada fixture budget/exfil adalah
hasil mekanisme yang diharapkan. Assertion test atau replay mismatch yang gagal
membuat exit code nonzero. `BLOCKED` pada unsupported review flow baseline
ditampilkan dalam artifact dan tidak disamarkan sebagai dukungan fitur penuh.

## Dua jenis waktu yang dipisahkan

**Protocol clock** tetap sumber expiry, lease dan freshness. Dalam replay clock
ini diinjeksi dari manifest, sehingga waktu seperti `2026-10-25T00:00:00+00:00`
tetap benar untuk scenario tersebut. Tick scheduler tetap logical order, bukan
detik. Field signed ticket `not_before`/`not_after`, nonce, payload hash,
footprint/version dan read receipt tidak diubah untuk menambahkan wall clock.

**Observation clock** baru memakai waktu UTC nyata host serta monotonic counter:

| Lokasi | Isi |
| --- | --- |
| Run/command/generator summary | `started_at_utc`, `finished_at_utc`, `duration_ns`, `process_id`. |
| `run.observed_timing.steps` | Window nyata setiap action scheduler, dihubungkan oleh action ID dan step index. |
| `hooks[].observed` | `observed_at_utc`, `monotonic_ns`, `process_id`; context task untuk receiver/ack. |
| Artifact `observed_timing.events` Fase 5 | Oracle event index/task/operation, source hook, actual observation time, protocol commit time dan export UTC. |
| Pair report / validation | Waktu comparison/generation dan window recording tiap mode. |
| Model tape | Waktu delegate call yang menghasilkan response/error yang direkam; replay tidak menulis ulang waktu recording lama. |
| `files.json` | Modified time nyata dan hash tiap file hasil, termasuk schema/catalog/manifest tanpa menyisipkan metadata ke policy definition. |
| JUnit XML | Timestamp nyata suite dan durasi masing-masing test sebagaimana pytest. |

Durasi memakai monotonic clock agar perubahan jam sistem tidak membuat durasi
negatif. Monotonic counter hanya dibandingkan dalam proses/run recording yang
sama. UTC tidak merupakan bukti clock synchronization antar mesin.

Hook mutation/receiver dipublikasikan setelah transaksi. Hook fallback yang
ditunda tetap ditandai `deferred`/`observed_after: fallback_release`; timestamp
adalah saat observer merekamnya, bukan klaim titik linearization SQL yang persis.
Timestamp receiver/ack dihubungkan melalui task/operation, tanpa mengubah
receipt/proof yang dipakai authorization. Event tanpa source timing dilaporkan
`source timing unavailable`, bukan memakai export time sebagai waktu efek.

Metadata baru bersifat observasional dan bukan authorization authority. Hanya
sidecar `observed_timing` di root result scheduler/artifact yang dikecualikan
dari semantic replay comparison. Tidak ada penghapusan field secara rekursif
dari payload worker, fakta, tiket, expiry atau receipt. Tests memeriksa bahwa
tampering pada field tersebut tetap terdeteksi dan replay lama tanpa metadata
observasi tetap dapat dibaca bila environment/registry-nya cocok.

Artifact/schema v1 menerima optional observational sidecar ini. Gunakan schema
dari run baru untuk metadata baru. File historis tidak di-backfill dengan waktu
peristiwa buatan; jalankan runner untuk membuat bukti recording yang baru.
Hash file mendukung pemeriksaan integritas lokal, bukan trusted timestamp atau
attestation cryptographic. Durasi observasi ini adalah diagnostik, belum merupakan
benchmark performa terkontrol atau pembuktian liveness/universal safety.

## Verifikasi aktual runner

Pada 27 Oktober 2026, command berikut selesai dengan status `PASSED`:

```powershell
.\.venv\Scripts\python.exe run_tests.py all --output .runs/testing/timestamps-verification
```

Hasil: 512 test lulus, 35 exact replay Fase 4 (34 scenario dan satu fallback),
serta 78 exact replay Fase 5 (13 scenario × enam mode). Seluruh 168 oracle events
pada artifact Fase 5 memiliki tautan ke observation hook bertimestamp. Semua
153 file dalam manifest hasil cocok dengan SHA-256 yang direkam. Laporan aktual
tersedia pada `.runs/testing/timestamps-verification/summary.json`.

Filter `scenarios --scenario budget --mode stateful_non_atomic` juga telah
dijalankan melalui CLI runner: recording dan replay lulus, dengan laporan pada
`.runs/testing/timestamps-filter-verification/summary.json`. Semua pemeriksaan
ini offline dan effects simulasi; live validation `NOT RUN`.
