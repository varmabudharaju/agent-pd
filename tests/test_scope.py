import os
from agent_pd import scope


def test_project_root_finds_git(tmp_path):
    (tmp_path / "proj" / ".git").mkdir(parents=True)
    sub = tmp_path / "proj" / "src"
    sub.mkdir()
    assert scope.project_root(str(sub)) == str(tmp_path / "proj")


def test_project_root_falls_back_to_cwd(tmp_path):
    d = tmp_path / "nogit"
    d.mkdir()
    assert scope.project_root(str(d)) == str(d)


def test_resolve_relative_and_home():
    assert scope.resolve("../x", "/a/b") == "/a/x"
    assert scope.resolve("~/y", "/a/b") == os.path.join(os.path.expanduser("~"), "y")


def test_classify_inside_clean():
    assert scope.classify("/proj/src/a.py", "/proj", [], [], project_boundary=True) == (None, None)


def test_classify_outside_is_boundary():
    kind, detail = scope.classify("/etc/passwd", "/proj", [], [], project_boundary=True)
    assert kind == "boundary"


def test_classify_sensitive_even_inside():
    pats = ["~/.ssh", ".env", "*.pem"]
    assert scope.classify("/proj/.env", "/proj", [], pats, project_boundary=True)[0] == "sensitive"
    home_key = os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa")
    assert scope.classify(home_key, "/proj", [], pats, project_boundary=True)[0] == "sensitive"


def test_classify_allowlist():
    kind, _ = scope.classify("/proj/tests/a.py", "/proj", ["src/"], [], project_boundary=True)
    assert kind == "allowlist"
    assert scope.classify("/proj/src/a.py", "/proj", ["src/"], [], project_boundary=True) == (None, None)


def test_classify_boundary_off():
    assert scope.classify("/etc/x", "/proj", [], [], project_boundary=False) == (None, None)
    # sensitive still fires with boundary off
    assert scope.classify("/etc/x.pem", "/proj", [], ["*.pem"], project_boundary=False)[0] == "sensitive"


def test_extract_paths():
    assert scope.extract_paths("cat ../secrets") == ["../secrets"]
    assert scope.extract_paths("ls /etc") == ["/etc"]
    assert scope.extract_paths("cd ..") == [".."]
    assert scope.extract_paths("find / -name foo") == ["/"]
    assert scope.extract_paths("git commit -m x") == []
    assert scope.extract_paths("npm test") == []
    assert scope.extract_paths("curl https://x.com/a") == []
    assert scope.extract_paths("echo hi > /etc/cfg") == ["/etc/cfg"]
    assert scope.extract_paths("sudo cat /root/.bashrc") == ["/root/.bashrc"]


def test_extract_paths_env_prefix_and_pipes():
    assert scope.extract_paths("FOO=bar cat /x") == ["/x"]
    assert scope.extract_paths("echo x | cat /secret") == ["/secret"]
    assert scope.extract_paths("A=1 B=2 sudo cat /root/.bashrc") == ["/root/.bashrc"]
