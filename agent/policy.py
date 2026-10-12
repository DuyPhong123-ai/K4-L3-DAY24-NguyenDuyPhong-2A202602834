"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
KNOWN_TOOLS = {"search_docs", "read_customer", "http_post"}


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    """Decide before tool execution; all outcomes include an audit reason."""
    if context.data_classification not in ("public", "internal", "restricted"):
        return False, "Unknown data classification"
    if type(context.egress_enabled) is not bool:
        return False, "egress_enabled must be a boolean"
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Restricted data cannot be used in a run with egress enabled"

    if not isinstance(context.agent_owner, str) or not context.agent_owner.strip():
        return False, "Missing agent owner"
    if type(context.delegation_depth) is not int or context.delegation_depth < 0:
        return False, "Delegation depth must be a non-negative integer"
    if not isinstance(context.principal_id, str) or not context.principal_id:
        return False, "Missing principal identity"
    try:
        principals = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, "Trusted principal data is unavailable or invalid"
    if not isinstance(principals, dict):
        return False, "Trusted principal data must be a mapping"
    principal = principals.get(context.principal_id)
    if not isinstance(principal, dict):
        return False, "Unknown principal identity"

    purposes = principal.get("purposes")
    allowed_tools = principal.get("allowed_tools")
    if not isinstance(purposes, list) or not isinstance(allowed_tools, list):
        return False, "Principal permissions are invalid"
    if not isinstance(context.request_purpose, str) or context.request_purpose not in purposes:
        return False, "Request purpose is not authorized for this principal"
    if not isinstance(context.requested_tool, str) or context.requested_tool not in KNOWN_TOOLS:
        return False, "Unknown or missing requested tool"
    if context.requested_tool not in allowed_tools:
        return False, "Requested tool is not authorized for this principal"
    if not isinstance(context.agent_scopes, (tuple, list)) or context.requested_tool not in context.agent_scopes:
        return False, "Requested tool is outside agent scopes"
    if context.delegation_depth > 0:
        if not isinstance(context.parent_scopes, (tuple, list)) or context.requested_tool not in context.parent_scopes:
            return False, "Requested tool is outside parent scopes"
    if context.requested_tool == "http_post" and not context.egress_enabled:
        return False, "http_post requires egress permission"

    if not isinstance(context.expires_at, str) or not context.expires_at:
        return False, "Missing delegation expiry"
    try:
        expiry = datetime.fromisoformat(context.expires_at)
    except ValueError:
        return False, "Invalid ISO-8601 delegation expiry"
    if expiry.tzinfo is None or expiry.utcoffset() is None:
        return False, "Delegation expiry must include a timezone"
    if expiry.utcoffset() != timedelta(0):
        return False, "Delegation expiry must be expressed in UTC"
    if expiry <= datetime.now(timezone.utc):
        return False, "Delegation has expired"

    return True, "Classification, principal, purpose, tool, scopes and expiry are valid"
