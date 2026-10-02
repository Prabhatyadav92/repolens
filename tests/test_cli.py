from repolens.cli import main


def project(tmp_path):
    (tmp_path / "app.py").write_text("import os\n\nprint('hi')\n")
    (tmp_path / "leak.py").write_text('token = "' + "gh" + "p_" + "a1B2" * 9 + '"\n')
    return tmp_path


def test_bare_path_runs_scan(tmp_path, capsys):
    code = main([str(project(tmp_path))])
    out = capsys.readouterr().out
    assert code == 0
    assert "Languages" in out and "unused-import" in out


def test_secrets_exit_code(tmp_path, capsys):
    assert main(["secrets", str(project(tmp_path))]) == 1
    assert "github-token" in capsys.readouterr().out
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.py").write_text("x = 1\n")
    assert main(["secrets", str(clean)]) == 0


def test_fail_on(tmp_path):
    root = project(tmp_path)
    assert main(["scan", str(root)]) == 0
    assert main(["scan", str(root), "--fail-on", "high"]) == 1


def test_report_file(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    project(root)
    out = tmp_path / "out.md"
    assert main(["report", str(root), "-o", str(out)]) == 0
    text = out.read_text()
    assert "## Secrets (1)" in text
    assert "a1B2a1B2" not in text


def test_missing_directory(capsys):
    assert main(["scan", "/definitely/not/here"]) == 2
    assert "not a directory" in capsys.readouterr().err
