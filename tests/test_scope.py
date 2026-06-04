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
    # absolute paths (caught either way)
    assert scope.extract_paths("FOO=bar cat /x") == ["/x"]
    assert scope.extract_paths("echo x | cat /secret") == ["/secret"]
    assert scope.extract_paths("A=1 B=2 sudo cat /root/.bashrc") == ["/root/.bashrc"]
    # discriminating: RELATIVE positional of a path-command after env-prefix / pipe.
    # The old single-command heuristic missed these (env-var treated as the binary; the
    # second pipe segment never inspected).
    assert scope.extract_paths("FOO=bar cat data.txt") == ["data.txt"]
    assert scope.extract_paths("echo x | cat secret") == ["secret"]


# --- Evasion 1: interpreter -c/-e one-liners hide the real file access ---

def test_extract_paths_interpreter_bash_c():
    assert "/etc/shadow" in scope.extract_paths("bash -c 'cat /etc/shadow'")


def test_extract_paths_interpreter_sh_c():
    assert "/etc/shadow" in scope.extract_paths("sh -c 'cat /etc/shadow'")


def test_extract_paths_interpreter_python_c():
    assert "/etc/shadow" in scope.extract_paths('python3 -c "open(\'/etc/shadow\').read()"')


def test_extract_paths_interpreter_node_e():
    assert "/etc/shadow" in scope.extract_paths(
        'node -e "require(\'fs\').readFileSync(\'/etc/shadow\')"')


def test_extract_paths_interpreter_ruby_e():
    assert "/etc/shadow" in scope.extract_paths('ruby -e "File.read(\'/etc/shadow\')"')


def test_extract_paths_interpreter_perl_e():
    assert "/etc/shadow" in scope.extract_paths('perl -e \'open(F, "/etc/shadow")\'')


def test_extract_paths_interpreter_does_not_over_recurse():
    # one level only: a quoted nested interpreter call still surfaces the leaf path
    paths = scope.extract_paths("bash -c 'cat ~/.ssh/id_rsa'")
    assert os.path.expanduser("~/.ssh/id_rsa") in paths or "~/.ssh/id_rsa" in paths


# --- Evasion 2: $VAR path indirection ---

def test_extract_paths_var_assignment_segment():
    assert "/etc/shadow" in scope.extract_paths("TARGET=/etc/shadow; cat $TARGET")


def test_extract_paths_var_assignment_env_prefix():
    assert "/etc/shadow" in scope.extract_paths("FOO=/etc/shadow cat $FOO")


def test_extract_paths_var_assignment_braced():
    assert "/etc/shadow" in scope.extract_paths("TARGET=/etc/shadow; cat ${TARGET}")


def test_extract_paths_unresolvable_var_does_not_crash():
    # $UNKNOWN is not an assignment we recorded; must not crash, just left/dropped
    res = scope.extract_paths("cat $UNKNOWN")
    assert isinstance(res, list)


# --- Evasion 3: in-project symlink to a sensitive dir (realpath) ---

def test_classify_follows_symlink_outside(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "id_rsa").write_text("k")
    link = proj / "link"
    try:
        os.symlink(str(secret), str(link))
    except OSError:
        import pytest
        pytest.skip("symlinks unsupported")
    abspath = scope.resolve(str(link / "id_rsa"), str(proj))
    kind, _ = scope.classify(abspath, str(proj), [], [], project_boundary=True)
    assert kind == "boundary"
