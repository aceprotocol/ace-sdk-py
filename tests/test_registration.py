import hashlib
import json
import pathlib
import runpy

import pytest

from ace import (
    AgentProfile,
    SoftwareIdentity,
    build_registration_payload,
    build_sign_data,
    create_registration_request,
    decode_signature,
    verify_signature,
)
from ace._utils import from_base64

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
VECTORS = json.loads((FIXTURES / "test-vectors.json").read_text())


@pytest.mark.parametrize("vector", VECTORS["vectors"]["registrations"])
def test_registration_authorization_interop(vector):
    a = VECTORS["agents"][vector["agent"]]
    identity = SoftwareIdentity(a["scheme"], from_base64(a["signingPrivateKey"]), from_base64(a["encryptionPrivateKey"]))
    request = vector["request"]
    opts = {} if vector["mode"] == "keep" else {"profile": None if vector["mode"] == "remove" else AgentProfile.from_dict(request["profile"])}
    assert create_registration_request(identity, timestamp=request["timestamp"], **opts) == request
    payload = build_registration_payload(request["encryptionPublicKey"], request["signingPublicKey"], request["scheme"], **opts)
    data = build_sign_data("register-request", request["aceId"], request["timestamp"], payload)
    assert data.hex() == vector["signDataHex"]
    assert verify_signature(data, decode_signature(request["authorization"], a["scheme"]), a["scheme"], identity.get_signing_public_key())
    assert not verify_signature(data, decode_signature(request["signature"], a["scheme"]), a["scheme"], identity.get_signing_public_key())


def test_fixture_digest():
    assert hashlib.sha256((FIXTURES / "test-vectors.json").read_bytes()).hexdigest() == json.loads((FIXTURES / "source.json").read_text())["sha256"]


def test_standalone_quickstart():
    runpy.run_path(str(pathlib.Path(__file__).parent.parent / "examples" / "quickstart.py"), run_name="__main__")
