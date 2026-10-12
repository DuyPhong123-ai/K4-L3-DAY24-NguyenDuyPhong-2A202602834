"""Policy validation cases beyond the minimum checkpoint tests."""
from dataclasses import replace

import pytest

from agent.policy import PolicyContext, check


VALID = PolicyContext(
    data_classification="restricted",
    request_purpose="support-reply",
    agent_owner="lab24-agent/run-b",
    delegation_depth=0,
    egress_enabled=False,
    principal_id="dpo",
    requested_tool="read_customer",
    agent_scopes=("read_customer",),
    expires_at="2099-01-01T00:00:00Z",
)


@pytest.mark.parametrize("changes", [
    {"data_classification": "unknown"},
    {"request_purpose": "unauthorized-purpose"},
    {"requested_tool": "unknown_tool"},
    {"agent_scopes": ()},
    {"agent_scopes": "read_customer"},
    {"delegation_depth": 1, "parent_scopes": ()},
    {"delegation_depth": -1},
    {"agent_owner": " "},
    {"expires_at": ""},
    {"expires_at": "invalid"},
    {"expires_at": "2099-01-01T00:00:00"},
    {"expires_at": "2099-01-01T00:00:00+07:00"},
])
def test_invalid_context_denied_with_reason(changes):
    allowed, reason = check(replace(VALID, **changes))
    assert allowed is False
    assert reason.strip()


def test_delegated_read_with_parent_permission_allowed():
    allowed, reason = check(replace(VALID, delegation_depth=1,
                                    parent_scopes=("read_customer",)))
    assert allowed is True
    assert reason.strip()
