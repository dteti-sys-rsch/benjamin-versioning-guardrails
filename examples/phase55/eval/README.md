# Suite evaluasi goal System B (pra-Fase 6)

Folder ini berisi file kasus berversi, manifest freeze, dan aturan menjalankan
`examples/phase55/live_27b_suite.py`. Semua file di sini ikut Git; hasil run
(`.runs/`) dan laporan naratif (`docs/`) tidak, jadi keduanya perlu dibackup
terpisah.

## File

| File | Isi |
| --- | --- |
| `dev-cases.json` | 10 kasus pengembangan (identik dengan goal suite v10). Dipakai untuk menyetel protokol v5–v10, jadi bukan bukti generalisasi. |
| `heldout-cases.json` | 22 kasus held-out: 2 parafrase per pola, separuh di workspace `alt` (nama resource/recipient lain, katalog 5 resource × 4 recipient), dan 2 policy multi-predikat. Ditulis sebelum run apa pun. |
| `adversarial-cases.json` | 9 goal negatif: budget terlampaui, eskalasi budget, goal kontradiktif, recipient ambigu, prompt injection di dokumen, release SENSITIVE, dan tool tak terdaftar (hapus, SQL, scraping). |
| `freeze.py` / `freeze.json` | Identitas protokol, schema, registry, versi worker, source kunci, dan file kasus. Suite menolak berjalan bila identitas saat ini berbeda. |

## Skema kasus

Setiap file punya `schema_version: 1`, `set`, `workspaces`, dan `cases`.
Validasinya dilakukan `atomicroot.evaluation.goal_eval.load_cases`, dan field
yang tidak dikenal ditolak.

- `workspaces.<nama>`: `resources` (`resource`, `content`, `label`, `purposes`),
  `recipients`, `enabled_tools`, `budget_limit`. Provider, limit, dan endpoint
  tetap milik host (`base_workspace` di suite).
- `cases.<nama>`: `pattern`, `goal`, `workspace`, `max_calls` (1–8), dan ground truth:
  - `accepted_outcomes`: himpunan kelas outcome yang benar (lihat `OUTCOMES`);
  - `required_effects`: pola `{tool, destination?, resource?}` yang harus *terkirim* bila outcome `SATISFIED`;
  - `forbidden_effects`: pola yang tidak boleh punya intent *diterima* (terkirim atau tidak);
  - `required_outputs`: himpunan id output yang tepat, atau `null` bila tidak diperiksa;
  - opsional: `clarification` (jawaban pengguna untuk `CLARIFY`), `mode: replan_stale` + `stale`,
    `labels_truth` (label ground truth, independen dari label sistem), `policy_probe`
    (request yang diuji ke Z3 dengan ekspektasi `ALLOW`/`DENY`), `reviewer_expect`
    (hanya untuk reviewer `case` di set development).

Oracle goal (`goal_oracle`) hanya membaca intent dan receipt di ledger. Ia tidak
melihat keputusan reviewer maupun keputusan guard. Monitor invariant Fase 5 tetap
dijalankan terpisah, memakai label truth dari kasus. Resource yang tidak
disebut di truth dianggap `UNKNOWN`.

## Reviewer

- `blind` (default): menyetujui setiap proposal bisnis yang valid, *pause* untuk
  spesifikasi capability (tidak pernah mengotorisasinya), menjawab klarifikasi
  dengan teks `clarification` milik penulis goal. Hasilnya mengukur planner + guard
  tanpa penyaring manusia.
- `case`: reviewer lama yang membaca `reviewer_expect`. Reviewer ini berbagi
  ekspektasi dengan penilaian, sehingga tidak independen. Pakai hanya untuk
  regression set development.

## Aturan bukti

- Folder output harus baru; run tidak pernah di-resume, ditimpa, atau dihapus.
- Infra error (koneksi, timeout) tercatat sebagai `INFRA_ERROR` dan tetap di denominator.
- Run ditolak bila tracked working tree dirty (kecuali `--allow-dirty`, yang dicatat di provenance).
- `provenance.json` mencatat: digest, quantization, dan versi server model; opsi
  (`num_ctx`, `think`, temperature); commit; status freeze; reviewer; cap; host fisik
  yang dideklarasikan.
- `MANIFEST.sha256` ditulis untuk seluruh file output.
- Cap: run dimulai hanya bila `total + 2 × max_calls ≤ --max-total-calls`.
  Faktor 2 menutup budget intake planning dan eksekusi yang terpisah.

## Urutan menjalankan

```powershell
# 1. Tree bersih dan ter-commit, lalu freeze
.\.venv\Scripts\python.exe examples/phase55/eval/freeze.py
git add examples/phase55/eval/freeze.json
git commit -m "Eval: freeze pra-Fase 6"
git tag phase5.5-freeze

# 2. SSH tunnel ke server model; endpoint sistem tetap localhost:11434
ssh -N -L 11434:localhost:11434 <user>@10.42.28.14

# 3. Live (budget total disetujui: <= 250 call)
.\.venv\Scripts\python.exe examples/phase55/live_27b_suite.py --cases-file examples/phase55/eval/heldout-cases.json --reviewer blind --max-total-calls 120 --declared-host 10.42.28.14 --output .runs/pre-phase6-heldout --authorize-live
.\.venv\Scripts\python.exe examples/phase55/live_27b_suite.py --cases-file examples/phase55/eval/adversarial-cases.json --reviewer blind --max-total-calls 40 --declared-host 10.42.28.14 --output .runs/pre-phase6-adversarial --authorize-live
.\.venv\Scripts\python.exe examples/phase55/live_27b_suite.py --cases-file examples/phase55/eval/heldout-cases.json --cases h-summary-base h-summary-alt h-payment-base h-parallel-alt h-email-base h-update-alt h-deploy-base h-clarify-alt h-permission-base h-policy2-base --repetitions 2 --reviewer blind --max-total-calls 90 --declared-host 10.42.28.14 --output .runs/pre-phase6-determinism --authorize-live
```

Pembagian cap 120 + 40 + 90 = 250 sesuai batas yang disetujui. Set determinisme
memakai 10 kasus × 2 ulangan agar `identical_response_rate` dihitung di dalam
satu run suite. Bila kasus
held-out gagal, hasil itu dilaporkan apa adanya. Protokol atau kasus tidak
disetel ulang sesudah freeze; perbaikan menjadi versi protokol baru dengan
held-out baru.

Untuk mereproduksi suite v10 lama: tambahkan `--cases-file examples/phase55/eval/dev-cases.json --reviewer case --no-freeze-check`.
Penilaian kini juga memakai oracle goal, jadi angkanya tidak harus identik dengan `.runs/dynamic-live-v10-27b`.
