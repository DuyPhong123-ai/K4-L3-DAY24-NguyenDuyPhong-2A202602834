"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
_TICKET_NAME = re.compile(r"ticket-([0-9]+)\.md")


def _ticket_id(filename: str) -> int | None:
    # The split lure's companion is the only supported filename exception.
    if filename == "ticket-904b.md":
        return 904
    match = _TICKET_NAME.fullmatch(filename)
    return int(match.group(1)) if match else None


def _authorize(*, principal_id, agent_id, run_id, expires_at, requested_tool,
               purpose, classification, scopes, parent_scopes, depth, args, ledger_path,
               egress_enabled=False):
    context = policy.PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=f"{agent_id}/{run_id}",
        delegation_depth=depth,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=requested_tool,
        agent_scopes=scopes,
        parent_scopes=parent_scopes,
        expires_at=expires_at,
    )
    allow, reason = policy.check(context)
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": run_id,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
        "tool": requested_tool,
        "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest(),
        "classification": classification,
        "decision": "allow" if allow else "deny",
        "reason": reason,
    }, ledger_path)
    return allow


def _run_a(message, llm, identity, ledger_path):
    if not _authorize(**identity, run_id=f"{identity['agent_id']}/run-a",
                      requested_tool="search_docs", purpose="summarize-tickets",
                      classification="internal", scopes=("search_docs",),
                      parent_scopes=(), depth=0, args={"query": message}, ledger_path=ledger_path):
        return [], "Không có quyền tìm ticket.", None
    docs = tools.search_docs(message)
    ticket_ids = sorted({ticket_id for doc in docs
                         if (ticket_id := _ticket_id(doc["id"])) is not None})
    injected = llm.find_injection("\n\n".join(doc["text"] for doc in docs))
    # Only the URL leaves A for the separate send decision; never customer IDs.
    target_url = injected.target_url if injected is not None else None
    sanitized_docs = [{"id": doc["id"], "text": pii.redact(doc["text"])} for doc in docs]
    return ticket_ids, llm.summarize(sanitized_docs), target_url


def _run_b(ticket_ids: list[int], identity, ledger_path):
    if not ticket_ids:
        return
    if any(type(ticket_id) is not int or ticket_id < 0 for ticket_id in ticket_ids):
        raise ValueError("Run B accepts only non-negative integer ticket IDs")
    run_id = f"{identity['agent_id']}/run-b"
    scopes = ("read_customer",)
    parent_scopes = ("search_docs", "read_customer")
    context = policy.PolicyContext(
        data_classification="restricted", request_purpose="support-reply",
        agent_owner=f"{identity['agent_id']}/{run_id}", delegation_depth=1,
        egress_enabled=False, principal_id=identity["principal_id"],
        requested_tool="read_customer", agent_scopes=scopes,
        parent_scopes=parent_scopes, expires_at=identity["expires_at"],
    )
    # Authorize before opening the private mapping, including for support_l1.
    allow, _ = policy.check(context)
    if not allow:
        _authorize(**identity, run_id=run_id, requested_tool="read_customer",
                   purpose="support-reply", classification="restricted", scopes=scopes,
                   parent_scopes=parent_scopes, depth=1, args={"ticket_ids": ticket_ids},
                   ledger_path=ledger_path)
        return
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    selected = set(ticket_ids)
    customer_ids = sorted({record["customer_id"] for record in customers
                           if selected.intersection(record.get("related_tickets", []))})
    for customer_id in customer_ids:
        if _authorize(**identity, run_id=run_id, requested_tool="read_customer",
                      purpose="support-reply", classification="restricted", scopes=scopes,
                      parent_scopes=parent_scopes, depth=1, args={"customer_id": customer_id},
                      ledger_path=ledger_path):
            # Private records stay in Run B; they never enter the LLM or egress.
            tools.read_customer(customer_id)


def _check_egress(target_url: str, identity, ledger_path):
    """Audit a proposed restricted-data send without receiving any records."""
    allowed = _authorize(
        **identity, run_id=f"{identity['agent_id']}/run-egress",
        requested_tool="http_post", purpose="support-reply",
        classification="restricted", scopes=("http_post",),
        parent_scopes=("http_post",), depth=1, egress_enabled=True,
        args={"url": target_url}, ledger_path=ledger_path,
    )
    if allowed:
        raise RuntimeError("Policy violated the restricted + egress deny rule")
    # No http_post on deny; this phase never receives a customer record.


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Ticket text in A, authorized reads in B, URL-only egress denial."""
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir is not None else DEFAULT_LEDGER_PATH
    identity = {
        "principal_id": principal_id,
        "agent_id": f"lab24-agent-{uuid4().hex}",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    }
    ticket_ids, summary, target_url = _run_a(message, llm, identity, ledger_path)
    _run_b(ticket_ids, identity, ledger_path)
    if target_url is not None:
        _check_egress(target_url, identity, ledger_path)
    return summary
