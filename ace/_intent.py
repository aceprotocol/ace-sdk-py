"""Cross-SDK operation identity; numbers are exact finite binary64 values."""

import hashlib
import json
import math
import struct

from .errors import ACEError


def intent_digest(value: object) -> str:
    def tree(v: object) -> list:
        if v is None:
            return ["null"]
        if isinstance(v, bool):
            return ["boolean", "true" if v else "false"]
        if isinstance(v, str):
            return ["string", v]
        if isinstance(v, (int, float)):
            try:
                number = float(v)
            except OverflowError:
                raise ACEError("invalid_body", "number exceeds binary64 range") from None
            if not math.isfinite(number) or (isinstance(v, int) and number != v):
                raise ACEError(
                    "invalid_body",
                    "number must be exactly representable as finite binary64; use a string",
                )
            return ["number", struct.pack(">d", 0.0 if number == 0 else number).hex()]
        if isinstance(v, list):
            return ["array", *(tree(item) for item in v)]
        if isinstance(v, dict):
            return ["object", *([key, tree(v[key])] for key in sorted(v))]
        raise ACEError("invalid_body", "not a JSON value")

    try:
        encoded = json.dumps(tree(value), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except UnicodeEncodeError:
        raise ACEError("invalid_body", "unpaired Unicode surrogate") from None
    return hashlib.sha256(b"ace.intent.v1\0" + encoded).hexdigest()
