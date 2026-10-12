"""Verify policy and ledger precede tools, with no private-store read on deny."""
import json
from pathlib import Path
from shutil import copy2

import pytest

from agent import ledger, tools
from agent.llm import MockLLM
from agent.runner import handle
from agent import runner


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "ticket-001.md").write_text("# Ticket #001\nKH-000777", encoding="utf-8")
    customers = tmp_path / "customers.json"
    customers.write_text(json.dumps([
        {"customer_id": "KH-000001", "related_tickets": [1]},
        {"customer_id": "KH-000777", "related_tickets": []},
    ]), encoding="utf-8")
    monkeypatch.setattr(tools, "CORPUS_DIR", corpus)
    monkeypatch.setattr(tools, "CUSTOMERS_FILE", customers)
    return customers


def test_support_never_opens_private_store(isolated_store, tmp_path, monkeypatch):
    original = Path.read_text

    def guarded_read(path, *args, **kwargs):
        assert path != isolated_store, "Denied principal opened private store"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    handle("ticket", MockLLM(), log_dir=tmp_path, principal_id="support_l1")
    entries = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert any(e["tool"] == "read_customer" and e["decision"] == "deny" for e in entries)


def test_allowed_tools_have_ledger_entry_before_execution(isolated_store, tmp_path, monkeypatch):
    path = tmp_path / "ledger.jsonl"
    seen = []
    for name in ("search_docs", "read_customer"):
        original = getattr(tools, name)

        def guarded(*args, _name=name, _original=original, **kwargs):
            latest = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
            assert latest["tool"] == _name and latest["decision"] == "allow"
            assert latest["on_behalf_of"] == "dpo"
            seen.append((_name, args[0]))
            return _original(*args, **kwargs)

        monkeypatch.setattr(tools, name, guarded)
    handle("ticket", MockLLM(), log_dir=tmp_path, principal_id="dpo")
    assert seen == [("search_docs", "ticket"), ("read_customer", "KH-000001")]
    assert ledger.verify(path)


def test_ledger_failure_stops_tool_execution(isolated_store, tmp_path, monkeypatch):
    def fail_append(*args, **kwargs):
        raise OSError("audit write failed")

    def forbidden_search(*args, **kwargs):
        pytest.fail("Tool executed without a ledger entry")

    monkeypatch.setattr(ledger, "append", fail_append)
    monkeypatch.setattr(tools, "search_docs", forbidden_search)
    with pytest.raises(OSError, match="audit write failed"):
        handle("ticket", MockLLM(), log_dir=tmp_path, principal_id="dpo")


@pytest.mark.parametrize("variant", [1, 2, 3, 4])
@pytest.mark.parametrize("principal", ["support_l1", "dpo"])
def test_each_lure_has_url_only_egress_denial(isolated_store, tmp_path, monkeypatch,
                                            variant, principal):
    source = Path(__file__).resolve().parents[1] / "corpus"
    names = [f"ticket-90{variant}.md"]
    if variant == 4:
        names.append("ticket-904b.md")
    for name in names:
        copy2(source / name, tools.CORPUS_DIR / name)
    records = json.loads(isolated_store.read_text(encoding="utf-8"))
    records.append({"customer_id": "KH-000999", "related_tickets": [900 + variant]})
    isolated_store.write_text(json.dumps(records), encoding="utf-8")
    real_check = runner._authorize
    real_read = tools.read_customer
    send_args = []
    reads = []

    def check_spy(**kwargs):
        if kwargs["requested_tool"] == "http_post":
            assert kwargs["classification"] == "restricted"
            assert kwargs["egress_enabled"] is True
            assert set(kwargs["args"]) == {"url"}
            send_args.append(kwargs["args"])
        return real_check(**kwargs)

    def read_spy(customer_id):
        reads.append(customer_id)
        return real_read(customer_id)

    def forbidden_post(*args, **kwargs):
        pytest.fail("Denied http_post was executed")

    monkeypatch.setattr(runner, "_authorize", check_spy)
    monkeypatch.setattr(tools, "read_customer", read_spy)
    monkeypatch.setattr(tools, "http_post", forbidden_post)
    handle("ticket", MockLLM(), log_dir=tmp_path, principal_id=principal)
    assert send_args == [{"url": "http://127.0.0.1:10024/reconcile"}]
    assert ("KH-000999" in reads) if principal == "dpo" else not reads
    entries = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    sends = [e for e in entries if e["tool"] == "http_post"]
    assert len(sends) == 1 and sends[0]["decision"] == "deny"
    assert "Restricted" in sends[0]["reason"]


def test_summary_receives_redacted_text(isolated_store, tmp_path):
    (tools.CORPUS_DIR / "ticket-001.md").write_text(
        "# Ticket #001\nCCCD 012345678912; STK 12345678; phone 0912345678; a@example.vn",
        encoding="utf-8")

    class InspectSummary(MockLLM):
        def summarize(self, docs):
            text = docs[0]["text"]
            for value in ("012345678912", "12345678", "0912345678", "a@example.vn"):
                assert value not in text
            for entity_type in ("VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"):
                assert f"[REDACTED_{entity_type}]" in text
            return super().summarize(docs)

    handle("ticket", InspectSummary(), log_dir=tmp_path, principal_id="dpo")
