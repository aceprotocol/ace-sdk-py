"""Invitations (05 § Invitations): the out-of-band pairing path (e.g. for a ``closed`` agent).

The inviter hands one peer, out of band, its own PublishedAgent and a delivery permit issued to
that peer (``NetworkClient.create_invitation``). Importing one verifies the agent and holds the
permit, and never admits the inviter.
"""

from __future__ import annotations

from .descriptor import VerifiedAgent, verify_published_agent
from .errors import ACEError
from .permit import verify_permit


def verify_invitation(
    value: object, subject: str, *, now: int, allow_loopback_relays: bool = False
) -> tuple[VerifiedAgent, dict]:
    """Verify an invitation addressed to ``subject``: the closed object ``{agent, permit}``,
    ``agent`` a valid PublishedAgent and ``permit`` valid under its KEL with ``issuer =
    agent.aceId`` and ``subject = subject`` (``invalid_authorization``)."""
    if not isinstance(value, dict) or set(value) != {"agent", "permit"}:
        raise ACEError("invalid_authorization", "invitation must be {agent, permit}")
    agent = verify_published_agent(
        value["agent"], now=now, allow_loopback_relays=allow_loopback_relays
    )
    if agent.ace_id == subject:
        raise ACEError("invalid_authorization", "an invitation from this identity to itself")
    return agent, verify_permit(value["permit"], agent.state, subject, now=now)
