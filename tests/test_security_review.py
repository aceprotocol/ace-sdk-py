"""Security review 2026-10-21 (docs/review-2026-10-21-security.md): C1-C11, the sdk-py items and
06 SP9. Each test fails without its fix."""

from __future__ import annotations

import copy
import fcntl
import socket
import sys
import time

import pytest

import ace._net as net
import ace.identity as identity_mod
import ace.kel as kel_mod
import ace.store as store_mod
from ace import (
    CORE,
    TEXT,
    ACEError,
    FileStore,
    Inbox,
    MemoryStore,
    PrekeyVault,
    Profiles,
    RelayClient,
    SoftwareIdentity,
    create_card_record,
    create_inception,
    create_permit,
    create_published_agent,
    create_rotation,
    create_signing_delegation,
    issue_delegation,
    verify_card_bundle,
    verify_kel,
    verify_published_agent,
)
from ace._encoding import check_json_value, loads_json, loads_object
from ace._relay_url import is_canonical_relay_url
from ace._xwing import CIPHERTEXT_SIZE, DecapsulationKey, _combiner, encapsulate
from ace.kel import reconcile_kel
from ace.keys import generate_software_key, key_digest
from ace.packet import parse_packet
from ace.relay import _SSE_FRAME_LIMIT, _SSELines, map_relay_response

from .helpers import Clock, Party, raises, wire
from .test_card_record import World as NetWorld
from .test_inbox import World

CONTACT_DIGEST = CORE.messages["ace:contact:1"].digest
RELAY = "https://relay.example"

# --- C1: relay URL host grammar (02 § HTTPS URLs) --------------------------------------------

BAD_RELAYS = (
    "https://[::1]",
    "https://a..b",
    "https://-a.example",
    "https://a-.example",
    "https://example.com.",
    "https://" + "a" * 64 + ".example",
)


@pytest.mark.parametrize("url", BAD_RELAYS)
def test_canonical_relay_url_needs_the_https_host_grammar(url):
    assert not is_canonical_relay_url(url, allow_loopback=False)
    assert not is_canonical_relay_url(url, allow_loopback=True)
    p = Party(Clock())
    source = p.source()
    source["descriptor"]["relays"] = [url]  # shape fails before the signature is looked at
    with raises("invalid_authorization"):
        verify_published_agent(source, now=p.clock.now)


def test_canonical_relay_urls_still_accepted():
    assert is_canonical_relay_url("https://relay.example/ace", allow_loopback=False)
    assert is_canonical_relay_url("http://127.0.0.1:8080", allow_loopback=True)
    assert is_canonical_relay_url("http://[::1]:8080", allow_loopback=True)


# --- C2: receipts pass step 9 and commit their seen entry -------------------------------------


def _receipt(w: World) -> bytes:
    mid = w.outbox.enqueue(w.b.id, "ace:text:1", {"message": "hi"})
    sent = []
    w.outbox.deliver(
        mid,
        lambda packet, agent: sent.append(packet),
        lambda ace_id, refresh=False: w.a.peers.agent(ace_id),
    )
    out = w.inbox.receive(wire(sent[0]))
    assert out.kind == "delivered"
    return wire(out.receipt.packet)


def test_a_replayed_receipt_is_a_duplicate_even_after_a_crash():
    w = World()
    raw = _receipt(w)
    assert w.a_inbox.receive(raw).kind == "delivered"
    assert w.a_inbox.receive(raw).kind == "duplicate"
    w.a_inbox._lock.release()  # crash before any snapshot: the seen entry is durable anyway
    again = Inbox.open(
        w.a.identity,
        w.a.store,
        w.a.vault,
        w.a.peers,
        Profiles(),
        on_message=lambda m: None,
        outbox=w.outbox,
        clock=w.clock,
    )
    assert again.receive(raw).kind == "duplicate"


def test_a_receipt_beyond_the_replay_horizon_is_dropped():
    w = World()
    raw = _receipt(w)
    w.a_inbox._replay._horizon = w.clock.now  # as if eviction raised it past the receipt
    out = w.a_inbox.receive(raw)
    assert out.kind == "dropped" and out.error.code == "replay_horizon"


# --- C3: a processed packet whose receipt cannot be sent is acked without quarantine ----------


def test_receipt_send_exhausting_the_budget_acks_without_quarantine():
    w = World()
    raw = wire(w.packet())

    def unreachable(reply):
        raise ACEError("relay_unavailable", "sender relay unreachable")

    kinds = [w.inbox.receive(raw, send_receipt=unreachable).kind for _ in range(3)]
    assert kinds == ["retry", "retry", "duplicate"]
    assert w.inbox.quarantined() == [] and w.b.store.list("inbox/attempts/") == []
    assert len(w.got) == 1


# --- C4: relay error strings lose control characters ------------------------------------------


def test_relay_error_strings_are_stripped_of_controls():
    body = b'{"error":"rate\\u001b[31m_limited","message":"slow\\r\\ndown\\u0085now\\u0007"}'
    err = map_relay_response(429, body, None)
    assert err.relay_code == "rate[31m_limited"
    assert err.message == "relay HTTP 429 rate[31m_limited: slowdownnow"


# --- C5: ReplayDetector default horizon (test_replay.test_defaults_use_clock) ----------------

# --- C6: signer refusals (01 § Rotation and recovery) -----------------------------------------


def test_next_root_committing_a_revealed_signing_key_is_refused():
    ident = SoftwareIdentity.generate(now=1000)
    signing = ident._signing
    with raises("invalid_argument"):
        ident.rotate(now=1001, next_root_digest=key_digest(signing.scheme, signing.public_key()))
    assert len(ident.get_kel()) == 2  # nothing appended


@pytest.mark.parametrize("which", ["_root", "_next_root"])
def test_delegating_the_current_or_next_root_is_refused(monkeypatch, which):
    ident = SoftwareIdentity.generate(now=1000)
    monkeypatch.setattr(identity_mod, "generate_software_key", lambda: getattr(ident, which))
    with raises("invalid_argument"):
        ident.delegate(now=1001)
    assert len(ident.get_kel()) == 2


def test_recovery_refuses_a_next_root_revealed_after_the_epoch_start():
    ident = SoftwareIdentity.generate(now=1000)
    ident.delegate(now=1001)  # its key is cut from the recovered log, yet revealed
    dropped = ident._signing
    with raises("invalid_argument"):
        SoftwareIdentity.recover(
            ident.get_kel(),
            ident._next_root,
            now=1002,
            next_root_digest=key_digest(dropped.scheme, dropped.public_key()),
        )


# --- C7: descriptor shape before KEL and signature work (04 § Verification) -------------------


def _broken_kel(source: dict) -> dict:
    source = copy.deepcopy(source)
    source["kel"] = source["kel"][:1]  # verifies, but is not usable: invalid_kel at step 2
    return source


def test_delegation_shape_is_checked_before_the_kel():
    p = Party(Clock())
    with raises("invalid_kel"):
        verify_published_agent(_broken_kel(p.source()), now=p.clock.now)
    for entries in ([{"kel": []}], [{"kel": [], "credential": {}}], [1]):
        source = _broken_kel(p.source())
        source["descriptor"]["delegations"] = entries
        with raises("invalid_authorization"):
            verify_published_agent(source, now=p.clock.now)
    good = issue_delegation(Party(p.clock).identity, p.id, now=p.clock.now)
    bad_sig = copy.deepcopy(good)
    bad_sig["credential"]["signature"]["value"] = "AAAA"
    for entry, code in ((bad_sig, "invalid_authorization"), ({**good, "kel": "x"}, "invalid_kel")):
        source = _broken_kel(p.source())  # a non-array kel is step 2's, not the entry's shape
        source["descriptor"]["delegations"] = [entry]
        with raises(code):
            verify_published_agent(source, now=p.clock.now)


def test_signature_value_length_is_shape():
    p = Party(Clock())
    source = _broken_kel(p.source())
    source["descriptor"]["signature"]["value"] = "AAAA"
    with raises("invalid_authorization"):
        verify_published_agent(source, now=p.clock.now)
    # under a good KEL too, before the seq is compared (never stale_peer_binding)
    source = p.source()
    source["descriptor"]["signature"].update(value="AAAA", seq=99)
    with raises("invalid_authorization"):
        verify_published_agent(source, now=p.clock.now)


# --- C8: one refresh per sender per interval, a transient failure included --------------------


def test_a_transiently_failed_refresh_still_suppresses_the_next_one():
    calls = []

    def refresh(ace_id):
        calls.append(ace_id)
        raise ACEError("relay_unavailable", "down")

    w = World(refresh=refresh)
    w.a.identity.delegate(now=w.clock.now)
    assert w.inbox.receive(wire(w.packet())).kind == "retry"
    assert w.inbox.receive(wire(w.packet())).kind == "retry"
    assert calls == [w.a.id]
    w.clock.now += 30
    assert w.inbox.receive(wire(w.packet())).kind == "retry"
    assert calls == [w.a.id] * 2


# --- C9: handle lookups report the pin's kel_live ---------------------------------------------


def test_handle_lookup_reports_the_pins_kel_live():
    world = NetWorld()
    try:
        alice = world.agent(contact="open", handle="alice")
        a = alice.identity.get_ace_id()
        bob = world.agent()
        fetch = bob._fetch

        def fetch_then_unconfirmed(ace_id, urls):
            agent = fetch(ace_id, urls)
            with bob.peers._store.lock("peers"):  # another writer: the pin is unconfirmed now
                bob.peers._update(ace_id, kel_live=False)
            return agent

        bob._fetch = fetch_then_unconfirmed
        _, card = bob.lookup_with_card(f"@alice@{world.host}")
        assert card.ace_id == a and card.kel_live is False
    finally:
        world.close()


# --- C10: verified-KEL cache ------------------------------------------------------------------


def test_unusable_kels_are_not_cached(monkeypatch):
    ident = SoftwareIdentity.generate(now=1000)
    icp_only = ident.get_kel()[:1]
    monkeypatch.setattr(kel_mod, "_verified", {})
    verify_kel(icp_only, 1000)
    key = kel_mod._prefix_keys(icp_only)[0][-1]
    assert key not in kel_mod._verified
    ident.delegate(now=1001, not_after=1100)
    expired = ident.get_kel()
    kel_mod._verified.clear()
    verify_kel(expired, 2000)
    assert kel_mod._prefix_keys(expired)[0][-1] not in kel_mod._verified
    verify_kel(expired, 1050)
    assert kel_mod._prefix_keys(expired)[0][-1] in kel_mod._verified


def test_kel_cache_holds_a_byte_budget(monkeypatch):
    kels = [SoftwareIdentity.generate(now=1000).get_kel() for _ in range(6)]
    monkeypatch.setattr(kel_mod, "_verified", {})
    monkeypatch.setattr(kel_mod, "_verified_bytes", 0)
    size = kel_mod._prefix_keys(kels[0])[1]
    monkeypatch.setattr(kel_mod, "_VERIFIED_CACHE_BYTES", 3 * size + size // 2)
    for k in kels:
        verify_kel(k, 1000)
    held = [kel_mod._prefix_keys(k)[0][-1] in kel_mod._verified for k in kels]
    assert held == [False, False, False, True, True, True]
    assert kel_mod._verified_bytes == sum(e[2] for e in kel_mod._verified.values()) <= 3.5 * size


# --- C11: list prefixes are validated like keys -----------------------------------------------


@pytest.mark.parametrize("make", [MemoryStore, lambda tmp: FileStore(tmp / "state")])
def test_list_prefix_is_validated(tmp_path, make):
    store = make(tmp_path) if make is not MemoryStore else MemoryStore()
    store.write("inbox/a.json", b"{}")
    for prefix in ("../", "inbox/../", "/", "inbox//", "Inbox/", ".", "a" * 201):
        with raises("invalid_argument"):
            store.list(prefix)
    assert store.list("") == store.list("inbox/") == store.list("inbox") == ["inbox/a.json"]


# --- sdk-py: duplicate keys, surrogates --------------------------------------------------------


def test_duplicate_json_keys_are_rejected():
    with pytest.raises(ValueError):
        loads_json(b'{"a":1,"a":2}')
    with pytest.raises(ValueError):
        loads_json(b'[{"x":{"b":1,"b":1}}]')
    w = World()
    raw = wire(w.packet()).replace(b'{"ace":"1",', b'{"ace":"1","ace":"1",', 1)
    assert raw.count(b'"ace":"1"') == 2
    with raises("invalid_packet"):
        parse_packet(raw)


@pytest.mark.parametrize(
    "raw", [b'{"a":"\\ud800"}', b'{"\\udfff":1}', b'{"a":["x\\udc00y"]}', b'{"a":"\\ude00\\ud83d"}']
)
def test_unpaired_surrogates_are_rejected_as_protocol_errors(raw):
    with raises("invalid_body"):
        loads_object(raw, "invalid_body", "body")
    with raises("invalid_packet"):
        check_json_value(loads_json(raw), "invalid_packet")
    assert loads_object(b'{"a":"\\ud83d\\ude00"}', "invalid_body", "body") == {"a": "\U0001f600"}


# --- sdk-py: PrekeyVault times are wire integers -----------------------------------------------


@pytest.mark.parametrize("bad", [-1, 1.5, True, "1", 1 << 53])
def test_prekey_vault_now_is_a_wire_int(bad):
    vault = PrekeyVault()
    pk = vault.current(now=1000)
    with raises("invalid_argument"):
        vault.current(now=bad)
    with raises("invalid_argument"):
        vault.open(pk.id, now=bad)
    with raises("invalid_argument"):
        vault.rotate(bad)
    with raises("invalid_argument"):
        vault.prune(bad)
    assert vault.open(pk.id, now=1000) is not None


# --- sdk-py: X25519 all-zero output is 32 zero bytes (03: no added check) ---------------------


def test_x25519_small_order_point_gives_zero_bytes_not_an_exception():
    key = DecapsulationKey(bytes(32))
    ct = bytes(CIPHERTEXT_SIZE)  # ct_X = 0: a small-order point
    ss = key.decapsulate(ct)
    ss_m = key._sk_m.decapsulate(ct[:1088])
    assert ss == _combiner(ss_m, bytes(32), bytes(32), key._pk_x)
    ss2, ct2 = encapsulate(key.public_key[:1184] + bytes(32))
    assert len(ss2) == 32 and len(ct2) == CIPHERTEXT_SIZE


# --- sdk-py: Retry-After bounded --------------------------------------------------------------


def test_retry_after_is_bounded():
    assert map_relay_response(503, b"", "0007").retry_after_seconds == 7
    assert map_relay_response(503, b"", "9999999999").retry_after_seconds == 9_999_999_999
    huge = map_relay_response(503, b"", "9" * 5000)  # beyond int()'s digit limit
    assert huge.retry_after_seconds == 9_999_999_999
    assert map_relay_response(503, b"", "1.5").retry_after_seconds is None


# --- sdk-py: RelayClient maps ValueError / UnicodeError ----------------------------------------


def test_relay_client_maps_unicode_errors(monkeypatch):
    client = RelayClient("https://" + "a" * 64 + ".example")
    monkeypatch.setattr(
        net, "_getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 443))]
    )
    ends = []

    def connect(addr, timeout=None):
        a, b = socket.socketpair()
        ends.extend((a, b))
        return a

    monkeypatch.setattr(net.socket, "create_connection", connect)
    try:
        with raises("relay_unavailable"):
            client.descriptor("ace:sha256:" + "a" * 64)
    finally:
        for s in ends:
            s.close()


# --- sdk-py: SSE line splitting is linear -----------------------------------------------------


class _Trickle:
    def __init__(self, data: bytes, step: int) -> None:
        self._data, self._pos, self._step = data, 0, step

    def read1(self, n: int) -> bytes:
        chunk = self._data[self._pos : self._pos + min(n, self._step)]
        self._pos += len(chunk)
        return chunk


def test_sse_lines_are_split_in_linear_time():
    line = b"data: " + b"x" * (_SSE_FRAME_LIMIT - 64)
    reader = _SSELines(_Trickle(line + b"\r\n\nid: 1\rnext\n", 16))
    start = time.monotonic()
    assert reader.next_line() == line
    assert time.monotonic() - start < 3  # the quadratic rescan took minutes
    assert [reader.next_line() for _ in range(4)] == [b"", b"id: 1", b"next", None]


# --- sdk-py: F_FULLFSYNC on macOS -------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
def test_file_store_uses_full_fsync_on_macos(tmp_path, monkeypatch):
    calls = []
    real = fcntl.fcntl

    def spy(fd, cmd, *args):
        calls.append(cmd)
        return real(fd, cmd, *args)

    monkeypatch.setattr(store_mod.fcntl, "fcntl", spy)
    FileStore(tmp_path / "state").write("a/b.json", b"{}")
    assert fcntl.F_FULLFSYNC in calls


# --- SP9: a known peer's contact source moves the pin only after dedupe and the rules ---------


def _contact(w: World, mid=None, ts=None) -> dict:
    body = {
        "kind": "request",
        "profile": TEXT.id,
        "note": "hello",
        "source": w.a.source(profiles=[TEXT.descriptor()]),
        "permit": create_permit(w.a.identity, w.b.id, now=w.clock.now),
    }
    return w.packet("ace:contact:1", body, CONTACT_DIGEST, ts=ts, mid=mid)


def test_a_dropped_contact_never_moves_the_pin():
    w = World()
    before = w.b.peers.state(w.a.id).seq
    w.a.identity.delegate(now=w.clock.now)  # the pin is now behind: contact-candidate path
    seen = _contact(w)
    w.inbox._see(seen["messageId"], w.a.id, seen["timestamp"])  # already processed
    assert w.inbox.receive(wire(seen)).kind == "duplicate"
    assert w.b.peers.state(w.a.id).seq == before
    w.clock.now += 30  # the next pin refresh is due (step 3 runs first)
    w.inbox._replay._horizon = w.clock.now  # beyond the horizon
    out = w.inbox.receive(wire(_contact(w)))
    assert out.kind == "dropped" and out.error.code == "replay_horizon"
    assert w.b.peers.state(w.a.id).seq == before
    w.clock.now += 30
    w.inbox._replay._horizon = 0
    assert w.inbox.receive(wire(_contact(w))).kind == "delivered"
    assert w.b.peers.state(w.a.id).seq == before + 1


# --- SP12: a document is never issued before its signing delegation ---------------------------


def _forks():
    """Two branches of one identity delegating the same key ``k`` at seq 2: ``a`` (a dlg, then
    ``k`` at 1001) and ``b``, which recovers ``a`` (a rot, then ``k`` at 1500)."""
    root, nxt, k = generate_software_key(), generate_software_key(), generate_software_key()
    icp = create_inception(root, key_digest(nxt.scheme, nxt.public_key()), 1000)
    s0 = verify_kel([icp], 1000)
    a = [icp, create_signing_delegation(s0, root, generate_software_key().public_key(), 1000)]
    a.append(create_signing_delegation(verify_kel(a, 1001), root, k.public_key(), 1001))
    rot = create_rotation(
        s0, nxt, key_digest("ml-dsa-65", generate_software_key().public_key()), 1500
    )
    b = [icp, rot]
    b.append(create_signing_delegation(verify_kel(b, 1500), nxt, k.public_key(), 1500))
    assert reconcile_kel(verify_kel(a, 1600), verify_kel(b, 1600))[1] == "recovered"
    return SoftwareIdentity(root, None, k, a, 1001), b


def test_a_document_of_a_recovered_branch_is_stale_under_the_new_kel():
    old, b = _forks()
    source = create_published_agent(old, relays=[RELAY], prekey=PrekeyVault().current(), now=1001)
    card = create_card_record(old, home=RELAY, contact="closed", listed=False, now=1001)
    verify_published_agent(source, now=1001)
    with raises("stale_peer_binding"):
        verify_published_agent({**source, "kel": b}, now=1600)
    with raises("stale_peer_binding"):
        verify_card_bundle({**card, "kel": b}, 1600)


def test_documents_are_issued_no_earlier_than_the_kels_last_event():
    ident = SoftwareIdentity.generate(now=2000)
    source = create_published_agent(ident, relays=[RELAY], prekey=PrekeyVault().current(), now=1900)
    assert source["descriptor"]["issuedAt"] == 2000
    verify_published_agent(source, now=1900)
    card = create_card_record(ident, home=RELAY, contact="closed", listed=False, now=1900)
    assert card["card"]["issuedAt"] == 2000
    verify_card_bundle(card, 1900)
