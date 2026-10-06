"""X-Wing hybrid KEM (draft-connolly-cfrg-xwing-kem-11) primitive tests.

Conformance against the draft's test vector 1 (seed -> public key, ciphertext ->
shared secret) lives in ``tests/test_interop_vectors.py``, driven by the shared
``ace-spec/test-vectors.json`` ``xwing`` block. This file covers round trips and
the byte-length checks that ``ace.xwing`` owns.
"""

import os

import pytest

from ace import xwing


def _keypair() -> tuple[bytes, bytes]:
    seed = os.urandom(xwing.SEED_SIZE)
    return seed, xwing.public_key_from_seed(seed)


def test_round_trip_random_keypair():
    seed, pk = _keypair()
    assert len(pk) == xwing.PUBLIC_KEY_SIZE
    ss_enc, ct = xwing.encapsulate(pk)
    assert len(ss_enc) == xwing.SHARED_SECRET_SIZE
    assert len(ct) == xwing.CIPHERTEXT_SIZE
    assert xwing.decapsulate(ct, seed) == ss_enc


def test_public_key_from_seed_is_deterministic():
    seed, pk = _keypair()
    assert xwing.public_key_from_seed(seed) == pk


def test_encapsulations_differ():
    _seed, pk = _keypair()
    ss1, ct1 = xwing.encapsulate(pk)
    ss2, ct2 = xwing.encapsulate(pk)
    assert ct1 != ct2
    assert ss1 != ss2


def test_decapsulate_wrong_seed_gives_different_secret():
    """ML-KEM implicit rejection: no error, but an unrelated secret."""
    _seed_a, pk_a = _keypair()
    seed_b, _pk_b = _keypair()
    ss, ct = xwing.encapsulate(pk_a)
    assert xwing.decapsulate(ct, seed_b) != ss


@pytest.mark.parametrize("length", [xwing.SEED_SIZE - 1, xwing.SEED_SIZE + 1])
def test_bad_seed_length_rejected(length):
    bad = b"\x01" * length
    with pytest.raises(ValueError, match=f"seed must be exactly 32 bytes, got {length}"):
        xwing.check_seed(bad)
    with pytest.raises(ValueError, match="seed"):
        xwing.public_key_from_seed(bad)
    with pytest.raises(ValueError, match="seed"):
        xwing.decapsulate(b"\x02" * xwing.CIPHERTEXT_SIZE, bad)


@pytest.mark.parametrize("length", [xwing.PUBLIC_KEY_SIZE - 1, xwing.PUBLIC_KEY_SIZE + 1])
def test_bad_public_key_length_rejected(length):
    bad = b"\x01" * length
    with pytest.raises(ValueError, match=f"public key must be exactly 1216 bytes, got {length}"):
        xwing.check_public_key(bad)
    with pytest.raises(ValueError, match="1216"):
        xwing.encapsulate(bad)


@pytest.mark.parametrize("length", [xwing.CIPHERTEXT_SIZE - 1, xwing.CIPHERTEXT_SIZE + 1])
def test_bad_ciphertext_length_rejected(length):
    seed, _pk = _keypair()
    bad = b"\x01" * length
    with pytest.raises(ValueError, match=f"ciphertext must be exactly 1120 bytes, got {length}"):
        xwing.check_ciphertext(bad)
    with pytest.raises(ValueError, match="1120"):
        xwing.decapsulate(bad, seed)
