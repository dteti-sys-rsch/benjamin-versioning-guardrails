# Laporan dan output verifikasi

Direktori ini menyimpan output test dan catatan hasil. Runtime state, signing
key, ledger, checkpoint, prompt, dan respons provider tetap berada di `.runs/`.

| Direktori | Isi |
| --- | --- |
| `phase35/` | Hasil historis Fase 3.5 |
| `phase36/` | Hasil Fase 3.6, JUnit regression, dan log baseline yang tersangkut |
| `phase37/` | Hasil Fase 3.7, JUnit baseline/targeted/regression, dan schedule yang tercatat |
| `providers/` | Hasil historis adapter/provider dan Ollama |
| `pilot/` | Hasil scope/progress pilot |
| `testing/` | Output test baru, misalnya `TEST_RESULTS.xml` |
| `cleanup/` | Manifest pemindahan dan hasil pemeriksaan kerapian repository |

JSON, XML, log, dan schedule historis dipindahkan tanpa mengubah isinya.
Command dan daftar file di dalamnya merekam lokasi **saat dijalankan**; path
lama tidak ditulis ulang menjadi command yang seolah pernah dijalankan.
`cleanup/MOVE_MANIFEST.json` memetakan path lama ke path baru serta SHA-256.
Jumlah test dan waktu pada arsip tidak menggantikan hasil test terbaru.

Output baru memakai path dari root repository, misalnya:

```powershell
python -m pytest -q --junitxml=reports/testing/TEST_RESULTS.xml
```

Laporan diabaikan Git, kecuali indeks ini dan tiga artefak Fase 3.7 yang sudah
terlacak sebelum perapian (`PHASE37_BASELINE.xml`, `PHASE37_TARGETED.xml`, dan
`PHASE37_SCHEDULES.json`). Ini mempertahankan kebijakan arsip sebelumnya.
Lihat [panduan CLI](../docs/testing/CLI_TESTING.md) untuk penggunaan dan batas
interpretasi status.
