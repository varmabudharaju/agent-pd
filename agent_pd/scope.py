"""Pure path-scope logic shared by the out_of_scope detector. No I/O except the
git-root walk in project_root(). Fully unit-testable."""
import fnmatch
import os
import shlex

# Bash commands whose first positional argument is a path even when it doesn't
# look like one (e.g. `cat foo.txt`, `cd build`).
PATH_COMMANDS = {"cat", "ls", "cd", "cp", "mv", "less", "more", "head", "tail",
                 "stat", "find", "du", "open", "code", "cmp", "diff", "rm",
                 "touch", "nano", "vim", "vi", "source"}
_URL_PREFIXES = ("http://", "https://", "ftp://")
_SHELL_OPS = {"|", "&&", "||", ";", "&", ">", ">>", "<", "2>", "2>>"}


def project_root(cwd: str) -> str:
    """Nearest ancestor of cwd containing a .git, else the (abs) cwd itself."""
    cur = os.path.abspath(cwd or os.getcwd())
    walker = cur
    while True:
        if os.path.isdir(os.path.join(walker, ".git")):
            return walker
        parent = os.path.dirname(walker)
        if parent == walker:
            return cur
        walker = parent


def resolve(path: str, cwd: str) -> str:
    """Expand ~, join against cwd if relative, normalize to an absolute path."""
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return os.path.normpath(p)


def _matches_sensitive(abspath: str, patterns: list):
    base = os.path.basename(abspath)
    for pat in patterns:
        expanded = os.path.normpath(os.path.expanduser(pat))
        if os.path.isabs(expanded):                 # dir/path prefix (e.g. ~/.ssh)
            if abspath == expanded or abspath.startswith(expanded + os.sep):
                return pat
        if fnmatch.fnmatch(base, pat):              # basename glob (*.pem, .env.*)
            return pat
    return None


def classify(abspath: str, root: str, scope_dirs: list, sensitive_patterns: list,
             project_boundary: bool = True):
    """Return (kind, detail). kind in {'sensitive','boundary','allowlist'} or (None, None)."""
    hit = _matches_sensitive(abspath, sensitive_patterns)
    if hit:
        return ("sensitive", hit)
    inside = abspath == root or abspath.startswith(root + os.sep)
    if not inside:
        return ("boundary", root) if project_boundary else (None, None)
    if scope_dirs:
        rel = os.path.relpath(abspath, root).replace(os.sep, "/")
        for d in scope_dirs:
            d = d.rstrip("/") + "/"
            if (rel + "/").startswith(d):
                return (None, None)
        return ("allowlist", scope_dirs)
    return (None, None)


def extract_paths(command: str) -> list:
    """Heuristically pull filesystem paths out of a Bash command. Conservative:
    a token is a path only if it looks like one (starts with / ~ ./ ..) or is the
    first positional argument of a known path-command. Flags, pipes, URLs ignored."""
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    if not toks:
        return []
    i = 1 if toks[0].rsplit("/", 1)[-1] == "sudo" and len(toks) > 1 else 0
    binary = toks[i].rsplit("/", 1)[-1] if i < len(toks) else ""
    out, seen_positional = [], False
    for t in toks[i + 1:]:
        if not t or t.startswith("-") or t in _SHELL_OPS:
            continue
        if t.startswith(_URL_PREFIXES):
            continue
        looks = t.startswith(("/", "~", "./", "../")) or t in ("..", ".")
        first_positional = not seen_positional
        seen_positional = True
        if looks or (binary in PATH_COMMANDS and first_positional):
            out.append(t)
    return out
