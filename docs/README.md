# Dokumentasi AtomicRoot

Semua perintah CLI pada dokumentasi dijalankan dari **root repository**, bukan
dari direktori dokumen. Entry point Python, package, fixture di `examples/`,
dan ledger/checkpoint di `.runs/` tetap memakai lokasi yang sama.

| Direktori | Isi |
| --- | --- |
| [testing/CLI_TESTING.md](testing/CLI_TESTING.md) | Perintah test, demo, konfigurasi, executor, dan cara membaca output |
| [phases/](phases/) | Catatan implementasi, audit, dan batas verifikasi setiap fase |
| [phases/scheduler-replay.md](phases/scheduler-replay.md) | Fase 4: audit fondasi, scheduler/replay, fallback dan coverage writer |
| [../examples/phase5/README.md](../examples/phase5/README.md) | Fase 5: katalog policy, six-mode matrix, guarded update dan oracle independen |
| [providers/PROVIDERS.md](providers/PROVIDERS.md) | Konfigurasi provider dan status integrasi |
| [providers/OLLAMA.md](providers/OLLAMA.md) | Konfigurasi serta hasil historis Ollama |
| [roadmap/AtomicRoot-Prompt-Fase-3.6-6-Revisi.md](roadmap/AtomicRoot-Prompt-Fase-3.6-6-Revisi.md) | Prompt lanjutan yang menjadi konteks roadmap |
| [roadmap/ATOMICROOT_MIGRASI_SISTEM_A_KE_B.md](roadmap/ATOMICROOT_MIGRASI_SISTEM_A_KE_B.md) | Rencana migrasi Sistem A menuju B |
| [design/blueprint.html](design/blueprint.html) | Blueprint historis, sebelumnya `wkwk.html` |

Dokumen fase, roadmap, provider, panduan CLI, dan blueprint tetap merupakan
catatan lokal yang diabaikan Git sesuai kebijakan repository sebelumnya, kecuali
catatan scheduler/replay Fase 4 dan policy evaluation Fase 5 yang disertakan
bersama source dan contoh replay.
[README utama](../README.md) dan [instruksi agent](../AGENTS.md) tetap di root.
Artefak verifikasi berada di [reports/](../reports/README.md); hasil lama tidak
menjadi bukti verifikasi ulang atau izin untuk melanjutkan fase berikutnya.
