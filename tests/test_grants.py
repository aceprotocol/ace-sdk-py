import pytest

from ace import (
    ResourcePolicy,
    execution_grant_digest,
    execution_intent_digest,
    verify_execution_grant_chain,
)
from tests.helpers import VECTORS, agent, peer_of, raises

V = VECTORS["vectors"]["grants"]


@pytest.mark.parametrize("c", V["cases"], ids=lambda c: c["name"])
def test_shared_resource_grants(c):
    def verify():
        return verify_execution_grant_chain(
            c["chain"],
            c["intent"],
            c["sender"],
            c["executor"],
            ResourcePolicy(
                V["cases"][0]["intent"]["resource"],
                peer_of(agent("alice")),
                c["epoch"],
                c["revoked"],
            ),
            c["now"],
        )

    if c["expected"] == "ok":
        assert verify() == V["intentDigest"]
    else:
        with raises(c["expected"]):
            verify()


def test_shared_intent_and_claims_digests():
    assert execution_intent_digest(V["cases"][0]["intent"]) == V["intentDigest"]
    assert execution_grant_digest(V["cases"][0]["chain"][0]) == V["rootDigest"]
