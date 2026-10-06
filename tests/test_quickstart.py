"""The README quickstart runs."""

import pathlib
import runpy


def test_quickstart_runs(capsys):
    runpy.run_path(str(pathlib.Path(__file__).parents[1] / "examples" / "quickstart.py"))
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("rfq ") and out[2] == "delivered" and out[-1] == "rfq"
