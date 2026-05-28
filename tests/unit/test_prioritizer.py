from joanfe.ingest.prioritizer import score_files
from joanfe.ingest.walker import SourceFile


def _src(rel_path: str, text: str) -> SourceFile:
    return SourceFile(path=None, rel_path=rel_path, text=text,  # type: ignore[arg-type]
                      line_count=text.count("\n") + 1)


def test_command_exec_and_sqli_score_higher_than_benign():
    files = [
        _src("benign.py", "def add(a, b):\n    return a + b\n"),
        _src("danger.py", "import os\nos.system('ping ' + host)\n"),
    ]
    scored = score_files(files)
    assert scored[0].source.rel_path == "danger.py"
    assert "command_exec" in scored[0].categories
    assert scored[-1].source.rel_path == "benign.py"
    assert scored[-1].score == 0


def test_categories_detected():
    sf = _src(
        "multi.py",
        "import pickle\npickle.loads(data)\nrequests.get(user_url)\n",
    )
    scored = score_files([sf])[0]
    assert "deserialization" in scored.categories
    assert "ssrf_network" in scored.categories


def test_hot_filename_bonus():
    plain = _src("util.py", "x = 1\n")
    hot = _src("auth.py", "x = 1\n")
    scored = {s.source.rel_path: s.score for s in score_files([plain, hot])}
    assert scored["auth.py"] > scored["util.py"]
