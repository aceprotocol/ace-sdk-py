"""Optional closed execution wrapper. Parsing confers no execution rights."""

import copy
import hashlib
import json

from .errors import ACEError
from .grants import execution_intent_digest
from .limits import MAX_EXECUTION_JSON_BYTES

EXECUTION_REQUEST_TYPE = "urn:ace:execute:1"
EXECUTION_REQUEST_SCHEMA = '{"fields":["intent","grants"],"type":"urn:ace:execute:1","version":1}'
EXECUTION_REQUEST_SCHEMA_DIGEST = hashlib.sha256(EXECUTION_REQUEST_SCHEMA.encode()).hexdigest()


def parse_execution_request(body: object) -> dict:
    """Only parse framing; the authoritative executor validates grants and effects."""
    try:
        if not isinstance(body, dict) or set(body) != {"intent", "grants"}:
            raise ValueError()
        grants = body["grants"]
        if (
            not isinstance(grants, list)
            or not 1 <= len(grants) <= 8
            or not all(isinstance(g, dict) for g in grants)
        ):
            raise ValueError()
        execution_intent_digest(body["intent"])
        if (
            len(
                json.dumps(
                    body, ensure_ascii=False, allow_nan=False, separators=(",", ":")
                ).encode()
            )
            > MAX_EXECUTION_JSON_BYTES
        ):
            raise ValueError()
        return copy.deepcopy(body)
    except (ValueError, TypeError, KeyError, RecursionError, ACEError) as exc:
        raise ACEError("invalid_authorization", "invalid execution request") from exc
