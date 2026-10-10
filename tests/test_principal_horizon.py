"""Principal horizon and registration-file merges across rotation and authority domains (02)."""

# ruff: noqa: E501

from __future__ import annotations

import dataclasses

from ace import MemoryStore, PeerStore, SoftwareIdentity, verify_peer_record
from ace._encoding import to_base64
from ace.principal import PrincipalSigner, create_principal_record
from ace.registration import create_registration_file, create_registration_request

from .helpers import raises

NOW = 1_800_000_000
ACC = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
ACC2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:9xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"


def _rec(owner, subject, issued_at=NOW - 10, roles=("controller",), account=ACC):
    return create_principal_record(
        PrincipalSigner.from_identity(owner), subject_signing_public_key=subject.get_signing_public_key(),
        account=account, roles=list(roles), expires_at=NOW + 3600, issued_at=issued_at,
    )


def _relay_record(ident, profile, ts=NOW):
    if "principal" in profile:
        profile = {**profile, "principal": profile["principal"].to_dict()}
    req = create_registration_request(ident, profile, timestamp=ts)
    return verify_peer_record(
        {"aceId": req["aceId"], "scheme": req["scheme"], "encryptionPublicKey": req["encryptionPublicKey"],
         "signingPublicKey": req["signingPublicKey"], "registrationSignature": req["signature"],
         "registeredAt": ts, "profile": req["profile"]},
        clock=lambda: NOW,
    )


def _file(ident, ts, principal=None):
    reg = create_registration_file(ident, name="n", endpoint="https://a.example/ace", timestamp=ts)
    return reg if principal is None else dataclasses.replace(reg, principal=principal)


def test_pin_before_horizons_gets_one_on_next_adopt_so_strip_then_replay_cannot_roll_back():
    owner, subject = SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    store = MemoryStore()
    older = _rec(owner, subject, issued_at=NOW - 100, roles=["controller"])
    newer = _rec(owner, subject, issued_at=NOW - 10, roles=["delegate"])
    PeerStore(store, clock=lambda: NOW).adopt(_relay_record(subject, {"principal": newer}))
    for k in store.list("principal-horizons/"):  # a store from before horizons
        store.delete(k)
    peers = PeerStore(store, clock=lambda: NOW)
    peers.adopt(_relay_record(subject, {"name": "n"}))  # the relay strips the principal
    with raises("invalid_principal"):
        peers.adopt(_relay_record(subject, {"principal": older}))


def test_registration_file_rotating_the_encryption_key_keeps_the_cached_principal():
    owner, subject = SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    peers = PeerStore(MemoryStore(), clock=lambda: NOW)
    principal = _rec(owner, subject)
    peers.adopt(_relay_record(subject, {"principal": principal}, ts=NOW - 50))
    exported = subject.export_private_key()
    exported["encryptionPrivateKey"] = to_base64(bytes([42]) * 32)
    rotated = SoftwareIdentity.from_export(exported)
    peer = peers.pin_registration_file(_file(rotated, NOW))
    assert peer.encryption_public_key == bytes(rotated.get_encryption_public_key())
    assert peer.principal == principal
    assert peers.get(subject.get_ace_id()).principal == principal


def test_registration_file_never_moves_an_unexpired_principal_to_another_authority_domain():
    x, y = SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    subject = SoftwareIdentity.generate("ed25519")
    peers = PeerStore(MemoryStore(), clock=lambda: NOW)
    in_x = _rec(x, subject, issued_at=NOW - 100)
    in_y = _rec(y, subject, issued_at=NOW - 10, account=ACC2, roles=["delegate"])
    peers.adopt(_relay_record(subject, {"principal": in_x}, ts=NOW - 60))
    peers.adopt(_relay_record(subject, {"principal": in_y}, ts=NOW - 50))  # the relay may move it
    # an endpoint re-attaches the older account's principal
    assert peers.pin_registration_file(_file(subject, NOW - 50, in_x)).principal == in_y


def test_registration_file_cannot_swap_in_a_principal_signed_by_someone_else():
    owner, attacker = SoftwareIdentity.generate("ed25519"), SoftwareIdentity.generate("ed25519")
    subject = SoftwareIdentity.generate("ed25519")
    peers = PeerStore(MemoryStore(), clock=lambda: NOW)
    legit = _rec(owner, subject)
    peers.adopt(_relay_record(subject, {"principal": legit}, ts=NOW - 50))
    forged = _rec(attacker, subject, issued_at=NOW - 5)
    assert peers.pin_registration_file(_file(subject, NOW - 50, forged)).principal == legit
