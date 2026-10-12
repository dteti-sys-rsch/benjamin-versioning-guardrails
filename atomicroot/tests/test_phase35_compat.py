from atomicroot.tests.phase3_support import System


def test_official_label_tightening_invalidates_prior_reader_release(tmp_path):
    s = System(tmp_path / "ledger.sqlite")
    s.read()
    ticket = s.auth(s.request("send-before-label-change"))
    assert ticket["decision"] == "ALLOW"
    s.runtime.labels.set_label("d", s.document["digest"], s.document["version"], "SENSITIVE", ["research"], s.owner)
    assert s.commit(ticket)["status"] == "STALE_TICKET"
    assert s.auth(s.request("send-after-label-change"))["decision"] == "DENY"
