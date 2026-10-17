import pathlib
import runpy


def test_quickstart_runs(capsys):
    runpy.run_path(str(pathlib.Path(__file__).parents[1] / "examples" / "quickstart.py"))
    assert "outbox status: delivered" in capsys.readouterr().out
