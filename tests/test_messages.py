"""create_message / parse_message: flows and the exact check order."""

from __future__ import annotations

import dataclasses
import os

import pytest

from ace import (
    ACEError,
    ReplayDetector,
    SoftwareIdentity,
    ThreadStateMachine,
    create_message,
    decode_envelope,
    parse_message,
    validate_body,
    verify_envelope_signature,
)
from ace._encoding import encode_signature, to_base64
from ace.encryption import encrypt
from ace.envelope import message_sign_data

from .helpers import peer_of, raises

NOW = 1_800_000_000


@pytest.fixture()
def world():
    alice, bob, carol = (SoftwareIdentity.generate(s) for s in ("ed25519", "secp256k1", "ed25519"))
    return {
        "alice": alice, "bob": bob, "carol": carol,
        "pa": peer_of(alice), "pb": peer_of(bob), "pc": peer_of(carol),
        "ta": ThreadStateMachine(alice.get_ace_id()), "tb": ThreadStateMachine(bob.get_ace_id()),
    }


def parse(w, env, *, receiver="bob", sender="pa", replay=None, **kw):
    threads = kw.pop("threads", w["tb"] if receiver == "bob" else w["ta"])
    return parse_message(
        env,
        w[receiver],
        w[sender],
        threads=threads,
        replay=replay or ReplayDetector(horizon=NOW - 1000),
        clock=lambda: NOW,
        **kw,
    )


def text(w, body=None, **kw):
    return create_message(
        w["alice"], w["pb"], "text", body or {"message": "hi"}, w["ta"], timestamp=NOW, **kw
    )


def resign(w, env, *, plaintext: bytes | None = None, signer="alice"):
    """Re-encrypt (optional) and re-sign an envelope as ``signer``."""
    env = dataclasses.replace(
        env,
        encryption=dataclasses.replace(env.encryption),
        signature=dataclasses.replace(env.signature),
    )
    if plaintext is not None:
        kem, payload = encrypt(plaintext, w["bob"].get_encryption_public_key(), env.conversation_id)
        env.encryption.kem_ciphertext, env.encryption.payload = to_base64(kem), to_base64(payload)
    env.signature.value = encode_signature(
        w[signer].sign(message_sign_data(env)), env.signature.scheme
    )
    return env


def test_full_economic_flow(world):
    w = world
    a, b, pa, pb, ta, tb = w["alice"], w["bob"], w["pa"], w["pb"], w["ta"], w["tb"]
    ra, rb = ReplayDetector(horizon=NOW - 1000), ReplayDetector(horizon=NOW - 1000)

    def send(src, dst_peer, src_threads, recv, src_peer, recv_threads, recv_replay, type_, body, i):
        env = create_message(
            src, dst_peer, type_, body, src_threads, thread_id="deal", timestamp=NOW + i
        )
        p = parse_message(
            decode_envelope(env.to_dict()),
            recv,
            src_peer,
            threads=recv_threads,
            replay=recv_replay,
            clock=lambda: NOW + i,
        )
        assert p.thread_id == "deal" and p.body == body
        assert src_threads.get_state(env.conversation_id, "deal") == recv_threads.get_state(
            env.conversation_id, "deal"
        )
        return env

    rfq = send(a, pb, ta, b, pa, tb, rb, "rfq", {"need": "translate", "ttl": 60}, 1)
    offer = send(b, pa, tb, a, pb, ta, ra, "offer", {"price": "5", "currency": "USDC"}, 2)
    accept = send(a, pb, ta, b, pa, tb, rb, "accept", {"offerId": offer.message_id}, 3)
    invoice = send(
        b,
        pa,
        tb,
        a,
        pb,
        ta,
        ra,
        "invoice",
        {"offerId": offer.message_id, "amount": "5", "currency": "USDC", "settlementMethod": "x"},
        4,
    )
    send(
        a,
        pb,
        ta,
        b,
        pa,
        tb,
        rb,
        "receipt",
        {
            "referenceId": invoice.message_id,
            "amount": "5",
            "currency": "USDC",
            "settlementMethod": "x",
            "proof": {"tx": "0x1"},
        },
        5,
    )
    deliver = send(b, pa, tb, a, pb, ta, ra, "deliver", {"type": "inline", "content": "bonjour"}, 6)
    send(a, pb, ta, b, pa, tb, rb, "confirm", {"deliverId": deliver.message_id}, 7)
    assert ta.get_state(rfq.conversation_id, "deal") == "confirmed" and ta.is_terminal(
        rfq.conversation_id, "deal"
    )
    snap = tb.get_snapshot(rfq.conversation_id, "deal")
    assert snap.peer_ace_id == a.get_ace_id() and snap.history[0].from_id == a.get_ace_id()
    assert accept.message_id == snap.history[2].message_id


def test_create_errors(world):
    w = world
    with raises("invalid_argument"):
        create_message(w["alice"], w["pb"], "rfq", {"need": "x"}, w["ta"])
    with raises("invalid_argument"):
        create_message(w["alice"], w["pb"], "bid", {}, w["ta"])  # type: ignore[arg-type]
    with raises("invalid_argument"):
        create_message(w["alice"], w["pb"], "text", {"message": "x"}, w["ta"], thread_id="")
    with raises("invalid_argument"):
        create_message(w["alice"], w["pb"], "text", {"message": "x"}, w["tb"])
    with raises("invalid_argument"):
        create_message(w["alice"], {"aceId": "x"}, "text", {"message": "x"}, w["ta"])  # type: ignore[arg-type]
    with raises("invalid_body"):
        text(w, {"message": 1})
    with raises("invalid_body"):
        text(w, {"message": "x", "n": float("nan")})
    with raises("invalid_body"):
        text(w, {"message": "x", "t": (1, 2)})
    with raises("limit_exceeded"):
        text(w, {"message": "x" * 65500})
    create_message(w["alice"], w["pb"], "rfq", {"need": "x"}, w["ta"], thread_id="t")
    with raises("wrong_role"):
        create_message(
            w["alice"], w["pb"], "offer", {"price": "1", "currency": "USDC"}, w["ta"], thread_id="t"
        )
    conv = next(iter(w["ta"].export_state())).conversation_id
    assert w["ta"].get_state(conv, "t") == "rfq"


def test_check_order(world):
    w = world
    env = text(w)
    assert parse(w, env).body == {"message": "hi"}
    # 2. wrong recipient (before everything else after decoding)
    to_carol = create_message(w["alice"], w["pc"], "text", {"message": "x"}, w["ta"], timestamp=NOW)
    with raises("wrong_recipient"):
        parse(w, to_carol, sender="pc")
    # 3. from must be the sender
    with raises("invalid_envelope"):
        parse(w, text(w), sender="pc")
    # 4. scheme mismatch
    forged = dataclasses.replace(
        text(w),
        signature=dataclasses.replace(env.signature, scheme="secp256k1", value="0x" + "11" * 65),
    )
    with raises("scheme_mismatch"):
        parse(w, forged)
    # 5. conversationId recomputed from verified keys
    with raises("invalid_envelope"):
        parse(w, resign(w, dataclasses.replace(text(w), conversation_id="ab" * 32)))
    # 6. timestamps and floor
    with raises("stale_timestamp"):
        parse(
            w,
            create_message(
                w["alice"], w["pb"], "text", {"message": "x"}, w["ta"], timestamp=NOW - 301
            ),
        )
    with raises("stale_timestamp"):
        parse(
            w,
            create_message(
                w["alice"], w["pb"], "text", {"message": "x"}, w["ta"], timestamp=NOW + 301
            ),
        )
    old = create_message(
        w["alice"], w["pb"], "text", {"message": "x"}, w["ta"], timestamp=NOW - 3600
    )
    assert parse(w, old, floor=NOW - 7200, replay=ReplayDetector(horizon=NOW - 7201)).body == {
        "message": "x"
    }
    with raises("invalid_argument"):
        parse(w, text(w), floor=NOW + 1)
    # 7/9. replay
    replay = ReplayDetector(horizon=NOW - 1000)
    once = text(w)
    parse(w, once, replay=replay)
    with raises("replay"):
        parse(w, once, replay=replay)
    # 8. bad signature commits nothing
    good = text(w)
    tampered = dataclasses.replace(
        good, encryption=dataclasses.replace(good.encryption, payload=to_base64(os.urandom(64)))
    )
    replay = ReplayDetector(horizon=NOW - 1000)
    with raises("invalid_signature"):
        parse(w, tampered, replay=replay)
    assert parse(w, good, replay=replay).body == {"message": "hi"}


def test_post_commit_failures_are_one_shot(world):
    w = world
    replay = ReplayDetector(horizon=NOW - 1000)
    garbage = resign(
        w,
        dataclasses.replace(
            text(w),
            encryption=dataclasses.replace(text(w).encryption, payload=to_base64(os.urandom(64))),
        ),
    )
    with raises("decryption_failed"):
        parse(w, garbage, replay=replay)
    with raises("replay"):
        parse(w, garbage, replay=replay)
    bad_body = resign(w, text(w), plaintext=b'{"message":1}')
    with raises("invalid_body"):
        parse(w, bad_body, replay=replay)
    not_json = resign(w, text(w), plaintext=b"\xff")
    with raises("invalid_body"):
        parse(w, not_json, replay=replay)


def test_identity_errors_are_local(world):
    w = world

    class Flaky:
        def __init__(self, inner, exc):
            self.inner, self.exc = inner, exc

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def decrypt(self, *a):
            raise self.exc

    w["flaky"] = Flaky(w["bob"], OSError("keychain locked"))
    with raises("identity_unavailable") as info:
        parse(w, text(w), receiver="flaky", threads=w["tb"])
    assert info.value.is_transient
    w["flaky"] = Flaky(w["bob"], ACEError("decryption_failed"))
    with raises("decryption_failed"):
        parse(w, text(w), receiver="flaky", threads=w["tb"])


def test_parse_argument_checks(world):
    w = world
    with raises("invalid_argument"):
        parse(w, text(w), threads=w["ta"])
    with raises("invalid_argument"):
        parse(w, text(w).to_dict())
    with raises("invalid_argument"):
        parse_message(text(w), w["bob"], {"aceId": "x"}, threads=w["tb"], replay=ReplayDetector())  # type: ignore[arg-type]


def test_economic_parse_applies_state_rules(world):
    w = world
    rfq = create_message(
        w["alice"], w["pb"], "rfq", {"need": "x"}, w["ta"], thread_id="t", timestamp=NOW
    )
    parse(w, rfq)
    # alice (the buyer) cannot offer; craft a correctly signed offer from alice anyway
    forged = resign(
        w,
        dataclasses.replace(rfq, type="offer", message_id="00000000-0000-4000-8000-000000000009"),
        plaintext=b'{"price":"1","currency":"USDC"}',
    )
    with raises("wrong_role"):
        parse(w, forged)


def test_verify_envelope_signature(world):
    w = world
    env = text(w)
    verify_envelope_signature(
        env, scheme="ed25519", signing_public_key=w["alice"].get_signing_public_key()
    )
    with raises("scheme_mismatch"):
        verify_envelope_signature(
            env, scheme="secp256k1", signing_public_key=w["bob"].get_signing_public_key()
        )
    with raises("invalid_signature"):
        verify_envelope_signature(
            env, scheme="ed25519", signing_public_key=w["carol"].get_signing_public_key()
        )


def test_validate_body_public():
    validate_body("text", {"message": "x", "extra": 1})
    with raises("invalid_body"):
        validate_body("text", [])  # type: ignore[arg-type]
    with raises("invalid_argument"):
        validate_body("nope", {})  # type: ignore[arg-type]
