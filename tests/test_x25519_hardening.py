"""X25519 degenerate-key rejection (parity with TS/Swift root safeguard).

The signing backend happens to reject low-order points today, but the invariant
"never derive a key from an all-zero shared secret" is now asserted explicitly so
it holds regardless of backend/version.
"""

import pytest

from ace.encryption import _reject_degenerate_shared_secret, encrypt

# Known Curve25519 low-order points (non-all-zero) — clamping collapses the shared
# secret to zero for these, so encrypting to them must fail.
_LOW_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",  # order 2
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",  # order 4
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 8
]


def test_reject_degenerate_shared_secret_invariant():
    # Non-zero secrets are fine.
    _reject_degenerate_shared_secret(bytes([1]) + b"\x00" * 31)
    _reject_degenerate_shared_secret(b"\x11" * 32)
    # All-zero secret is rejected loudly.
    with pytest.raises(ValueError, match="degenerate"):
        _reject_degenerate_shared_secret(b"\x00" * 32)


@pytest.mark.parametrize("hex_point", _LOW_ORDER)
def test_encrypt_rejects_low_order_points(hex_point):
    with pytest.raises(ValueError):
        encrypt(b"secret", bytes.fromhex(hex_point), "conv")
