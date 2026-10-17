"""Optional commerce profile: rules wired into Outbox (send) and Inbox (receive)."""

import pytest

from ace import (
    COMMERCE,
    TEXT,
    ACEError,
    Inbox,
    Outbox,
    Profiles,
    commerce_rules,
    decode_content,
    decode_packet,
    decrypt_packet,
)
from ace.commerce import (
    ACCEPT,
    CONFIRM,
    DELIVER,
    INVOICE,
    OFFER,
    PAYMENT,
    REJECT,
    RFQ,
    ThreadStore,
    validate_commerce_ext,
)
from ace.rules import MessageEvent
from tests.helpers import Clock, Party, raises, wire

PROFILES = Profiles([TEXT, COMMERCE])
STABLE = {
    "method": "stablecoin",
    "asset": "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "recipient": "0xabc",
}


class Market:
    def __init__(self):
        self.clock = Clock()
        self.buyer, self.seller = Party(self.clock), Party(self.clock)
        for x, y in ((self.buyer, self.seller), (self.seller, self.buyer)):
            x.peers.adopt(y.source())
            x.peers.set_status(y.id, "admitted")
        self.rules = {p.id: commerce_rules(p.store, p.id) for p in (self.buyer, self.seller)}
        self.outbox = {
            p.id: Outbox(p.identity, p.store, PROFILES, rules=[self.rules[p.id]], clock=self.clock)
            for p in (self.buyer, self.seller)
        }
        self.inbox = {
            p.id: Inbox.open(
                p.identity,
                p.store,
                p.vault,
                p.peers,
                PROFILES,
                on_message=lambda m: None,
                rules=[self.rules[p.id]],
                outbox=self.outbox[p.id],
                clock=self.clock,
            )
            for p in (self.buyer, self.seller)
        }

    def post(self, frm, to, type_, body, thread="t1"):
        """Enqueue at ``frm`` (send-side check) and produce the packet; nothing is received."""
        mid = self.outbox[frm.id].enqueue(to.id, type_, body, thread_id=thread)
        sent = []
        self.outbox[frm.id].deliver(
            mid, lambda p, ag: sent.append(p), lambda a, refresh=False: frm.peers.agent(a)
        )
        return mid, sent[0]

    def receive(self, frm, to, packet):
        """``to`` receives ``packet``; its receipt is handed back to ``frm``."""
        out = self.inbox[to.id].receive(wire(packet))
        if out.receipt is not None:
            self.inbox[frm.id].receive(wire(out.receipt.packet))
        return out

    def send(self, frm, to, type_, body, thread="t1"):
        """Enqueue at ``frm``, deliver, receive at ``to``, return the receipt to ``frm``."""
        mid, packet = self.post(frm, to, type_, body, thread)
        return mid, self.receive(frm, to, packet)

    def state(self, party, thread="t1"):
        from ace._encoding import conversation_key

        t = self.rules[party.id].threads.get(
            conversation_key(self.buyer.id, self.seller.id), thread
        )
        return None if t is None else t.state


def test_full_flow_with_stablecoin_settlement():
    m = Market()
    b, s = m.buyer, m.seller
    _, out = m.send(b, s, RFQ, {"need": "translate"})
    assert out.kind == "delivered" and m.state(b) == m.state(s) == "requested"
    offer, _ = m.send(s, b, OFFER, {"price": "10", "currency": "USDC"})
    accept, _ = m.send(b, s, ACCEPT, {"offerId": offer})
    invoice, _ = m.send(
        s, b, INVOICE, {"offerId": offer, "amount": "10", "currency": "USDC", "settlement": STABLE}
    )
    _, out = m.send(
        b,
        s,
        PAYMENT,
        {
            "referenceId": invoice,
            "amount": "10",
            "currency": "USDC",
            "settlement": {"method": "stablecoin", "proof": {"txHash": "0xdead"}},
        },
    )
    assert out.kind == "delivered" and m.state(s) == "paid"
    deliver, _ = m.send(s, b, DELIVER, {"type": "inline", "content": "bonjour"})
    m.send(b, s, CONFIRM, {"deliverId": deliver})
    assert m.state(b) == m.state(s) == "confirmed"
    assert accept


def test_send_side_checks_and_receive_rejections():
    m = Market()
    b, s = m.buyer, m.seller
    with raises("invalid_body"):  # commerce requires a threadId
        m.outbox[b.id].enqueue(s.id, RFQ, {"need": "x"})
    with raises("transition_not_allowed"):
        m.outbox[b.id].enqueue(s.id, OFFER, {"price": "1", "currency": "USDC"}, thread_id="t1")
    m.send(b, s, RFQ, {"need": "x"})
    with raises("wrong_role"):
        m.outbox[b.id].enqueue(s.id, OFFER, {"price": "1", "currency": "USDC"}, thread_id="t1")
    offer, _ = m.send(s, b, OFFER, {"price": "1", "currency": "USDC"})
    with raises("bad_reference"):
        m.outbox[b.id].enqueue(
            s.id, ACCEPT, {"offerId": "00000000-0000-4000-8000-000000000000"}, thread_id="t1"
        )
    _, out = m.send(b, s, REJECT, {"reason": "too much"})
    assert m.state(s) == "rejected"
    with raises("transition_not_allowed"):  # terminal
        m.outbox[s.id].enqueue(b.id, OFFER, {"price": "1", "currency": "USDC"}, thread_id="t1")
    assert offer and out.kind == "delivered"


def test_sender_commits_on_the_delivered_receipt_and_the_thread_is_busy_until_then():
    m = Market()
    b, s = m.buyer, m.seller
    mid, packet = m.post(b, s, RFQ, {"need": "x"})
    assert m.state(b) is None  # nothing committed at enqueue
    assert m.outbox[b.id].busy(s.id, "t1") == mid
    with raises("thread_busy"):
        m.outbox[b.id].enqueue(s.id, RFQ, {"need": "again"}, thread_id="t1")
    m.outbox[b.id].enqueue(s.id, RFQ, {"need": "other"}, thread_id="t2")  # other threads are free
    m.receive(b, s, packet)
    assert m.state(b) == m.state(s) == "requested"
    assert m.outbox[b.id].busy(s.id, "t1") is None
    # a rejected receipt changes nothing and frees the thread
    m.outbox[s.id].enqueue(b.id, OFFER, {"price": "1", "currency": "USDC"}, thread_id="t1")
    mid2 = m.outbox[s.id].entries("pending")[0].message_id
    m.outbox[s.id].settle(mid2, "rejected", "bad_reference", sender=b.id)
    assert m.state(s) == "requested" and m.outbox[s.id].busy(b.id, "t1") is None
    # abandoning frees it too
    m.outbox[s.id].enqueue(b.id, OFFER, {"price": "1", "currency": "USDC"}, thread_id="t1")
    m.outbox[s.id].abandon(m.outbox[s.id].entries("pending")[0].message_id)
    assert m.outbox[s.id].busy(b.id, "t1") is None and m.state(s) == "requested"


def test_glare_crossing_messages_are_both_rejected_thread_busy():
    m = Market()
    b, s = m.buyer, m.seller
    m.send(b, s, RFQ, {"need": "x"})
    offer1, _ = m.send(s, b, OFFER, {"price": "5", "currency": "USDC"})
    accept, p_accept = m.post(b, s, ACCEPT, {"offerId": offer1})
    offer2, p_offer2 = m.post(s, b, OFFER, {"price": "4", "currency": "USDC"})
    # both packets arrive before either receipt
    out_s = m.inbox[s.id].receive(wire(p_accept))
    out_b = m.inbox[b.id].receive(wire(p_offer2))
    m.inbox[b.id].receive(wire(out_s.receipt.packet))
    m.inbox[s.id].receive(wire(out_b.receipt.packet))
    assert out_s.kind == out_b.kind == "rejected"
    assert out_s.error.code == out_b.error.code == "thread_busy"
    assert m.outbox[b.id].get(accept).status == "rejected"
    assert m.outbox[s.id].get(offer2).status == "rejected"
    assert m.state(b) == m.state(s) == "offered"
    m.send(b, s, ACCEPT, {"offerId": offer1})
    assert m.state(b) == m.state(s) == "accepted"


def test_receiver_rejects_with_the_rule_code():
    m = Market()
    b, s = m.buyer, m.seller
    # the seller's own state disagrees: an offer in a thread the seller never saw
    store = ThreadStore(b.store, b.id)
    from ace import create_packet, encode_content

    plain = encode_content(
        OFFER, COMMERCE.messages[OFFER].digest, {"price": "1", "currency": "USDC"}, "t9"
    )
    p = create_packet(s.identity, b.id, b.vault.current(), plain, timestamp=m.clock.now)
    out = m.inbox[b.id].receive(wire(p))
    assert out.kind == "rejected" and out.error.code == "transition_not_allowed"
    assert store.list() == []


def test_settlement_shapes():
    ts = ThreadStore(Party(Clock()).store, "ace:sha256:" + "a" * 64)
    other = "ace:sha256:" + "b" * 64

    def ev(type_):
        return MessageEvent(
            "receive", "00000000-0000-4000-8000-000000000001", other, ts.local, 1, type_, "t"
        )

    for bad in (
        {**STABLE, "extra": 1},
        {**STABLE, "asset": "usdc"},
        {**STABLE, "recipient": ""},
        {"method": "stripe-link", "url": "http://pay.example"},
        {"method": "stripe-link", "url": "https://pay.example", "memo": "x"},
    ):
        with raises("invalid_body"):
            ts.decide(
                ev(INVOICE), {"offerId": "x", "amount": "1", "currency": "USD", "settlement": bad}
            )
    with raises("invalid_body"):
        ts.decide(
            ev(PAYMENT),
            {
                "referenceId": "x",
                "amount": "1",
                "currency": "USD",
                "settlement": {"method": "stripe-link", "proof": {"txHash": "0x"}},
            },
        )
    validate_commerce_ext(
        {
            "settlement": [
                {"method": "stripe-link"},
                {"method": "stablecoin", "asset": STABLE["asset"]},
            ]
        }
    )
    for bad in (
        {"settlement": [{"method": "stripe-link"}] * 2},
        {"settlement": []},
        {"settlement": [{"method": "cash"}]},
    ):
        with raises("invalid_authorization"):
            validate_commerce_ext(bad)


def test_expiry_releases_the_thread_without_a_state_change():
    from ace.limits import OFFLINE_WINDOW_SECONDS

    m = Market()
    b, s = m.buyer, m.seller
    mid, _ = m.post(b, s, RFQ, {"need": "x"})
    m.clock.now += OFFLINE_WINDOW_SECONDS + 1
    m.outbox[b.id].deliver(mid, lambda p, ag: None, lambda a, refresh=False: b.peers.agent(a))
    assert m.outbox[b.id].get(mid).status == "expired"
    assert m.outbox[b.id].busy(s.id, "t1") is None and m.state(b) is None


@pytest.mark.parametrize("crash", ["after_journal", "after_commit", "after_on_message"])
@pytest.mark.parametrize("recover", ["reopen", "resend"])
def test_interrupted_delivery_recovers_rules_and_host_exactly_once(crash, recover):
    m = Market()
    b, s = m.buyer, m.seller
    m.inbox[s.id].close()
    rules, host, armed = m.rules[s.id], set(), [True]

    def interrupt(point):
        if crash == point and armed:
            armed.clear()
            raise ACEError("storage_failed", "simulated crash")

    real_apply = rules.threads.apply

    def apply(e, body):
        interrupt("after_journal")
        return real_apply(e, body)

    def on_message(msg):
        interrupt("after_commit")
        host.add((msg.from_id, msg.message_id))
        interrupt("after_on_message")

    rules.threads.apply = apply

    def open_inbox():
        return Inbox.open(
            s.identity,
            s.store,
            s.vault,
            s.peers,
            PROFILES,
            on_message=on_message,
            rules=[rules],
            outbox=m.outbox[s.id],
            clock=m.clock,
        )

    inbox = open_inbox()
    mid, packet = m.post(b, s, RFQ, {"need": "x"})
    assert inbox.receive(wire(packet)).kind == "retry"
    if recover == "reopen":
        inbox.close()
        inbox = open_inbox()
    out = inbox.receive(wire(packet))
    assert out.kind == "duplicate"
    receipt = decode_content(decrypt_packet(decode_packet(out.receipt.packet), b.vault))["body"]
    assert receipt["messageId"] == mid and receipt["outcome"] == "delivered"
    assert host == {(b.id, mid)}
    from ace._encoding import conversation_key

    t = rules.threads.get(conversation_key(b.id, s.id), "t1")
    assert t is not None and [h["messageId"] for h in t.history] == [mid]
    m.inbox[b.id].receive(wire(out.receipt.packet))
    assert m.state(b) == "requested" and m.outbox[b.id].get(mid).status == "delivered"


def test_a_late_receipt_settles_an_abandoned_entry():
    m = Market()
    b, s = m.buyer, m.seller
    mid, packet = m.post(b, s, RFQ, {"need": "x"})
    m.outbox[b.id].abandon(mid)
    assert m.outbox[b.id].get(mid).status == "expired" and m.state(b) is None
    out = m.receive(b, s, packet)  # the seller processed it anyway; its receipt arrives late
    assert out.kind == "delivered" and m.state(s) == "requested"
    assert m.outbox[b.id].get(mid).status == "delivered" and m.state(b) == "requested"
    offer, out = m.send(s, b, OFFER, {"price": "1", "currency": "USDC"})
    assert out.kind == "delivered"
    _, out = m.send(b, s, ACCEPT, {"offerId": offer})
    assert out.kind == "delivered" and m.state(b) == m.state(s) == "accepted"


def test_open_thread_limit_counts_markers(monkeypatch):
    import ace.commerce as commerce

    monkeypatch.setattr(commerce, "MAX_OPEN_THREADS_PER_PEER", 2)
    store = Party(Clock()).store
    local, peer = "ace:sha256:" + "a" * 64, "ace:sha256:" + "b" * 64
    ts = ThreadStore(store, local)

    def ev(i, type_, thread, frm=peer):
        to = local if frm == peer else peer
        return MessageEvent(
            "receive", f"00000000-0000-4000-8000-00000000000{i}", frm, to, i, type_, thread
        )

    ts.apply(ev(1, RFQ, "t1"), {})
    ts.apply(ev(2, RFQ, "t2"), {})
    with raises("limit_exceeded"):
        ts.decide(ev(3, RFQ, "t3"), {})
    ts.apply(ev(4, REJECT, "t1", frm=local), {})  # an ended thread frees its slot
    assert len(store.list("commerce/open/")) == 1
    ts.decide(ev(5, RFQ, "t3"), {})
    ts.apply(ev(6, RFQ, "t3"), {})
    with raises("limit_exceeded"):
        ThreadStore(store, local).decide(ev(7, RFQ, "t4"), {})
