"""Pure path-scope logic shared by the out_of_scope detector. No I/O except the
git-root walk in project_root(). Fully unit-testable."""
import fnmatch
import os
import re
import shlex

# Bash commands whose first positional argument is a path even when it doesn't
# look like one (e.g. `cat foo.txt`, `cd build`).
PATH_COMMANDS = {"cat", "ls", "cd", "cp", "mv", "less", "more", "head", "tail",
                 "stat", "find", "du", "open", "code", "cmp", "diff", "rm",
                 "touch", "nano", "vim", "vi", "source"}
_URL_PREFIXES = ("http://", "https://", "ftp://")
_SHELL_OPS = {"|", "&&", "||", ";", "&", ">", ">>", "<", "2>", "2>>"}
_SEG_RE = re.compile(r"\|\||&&|\||;")          # split compound commands into segments
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Interpreters that take a script body via -c/-e; the sensitive path can hide
# inside that quoted argument, so we recurse into it (Evasion 1).
_INTERPRETERS = {"bash", "sh", "zsh", "python", "python3", "python2",
                 "ruby", "node", "perl"}
# Pull candidate paths out of an interpreter script body. Two sources:
#  (1) ANY quoted ('...'/"...") string literal — a bare basename like '.env' or
#      'id_rsa' hides here and only classifies to an offense if it actually resolves
#      to / matches something sensitive or out-of-project; benign literals ('hello',
#      'ls', 'w') classify to None and are harmless.
#  (2) bare tokens that start with /, ~, ./ or ../ (unquoted path literals).
_SCRIPT_PATH_RE = re.compile(
    r"""['"]([^'"]*)['"]"""                           # any quoted string literal
    r"""|(?<![\w'"])((?:/|~/|\.\.?/)[^\s'")(,;]+)"""  # bare absolute/home/relative
)
# Cap candidate length so a quoted blob of prose/code isn't treated as a path.
_MAX_SCRIPT_CAND = 256
# A real path/basename uses only these chars. Anything else (=[](){},:;) means the
# candidate is a code/JSON fragment that mismatched-quote pairing pulled out, not a path.
_SAFE_PATH_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/~*-"
)
# A simple literal $VAR / ${VAR} reference (Evasion 2).
_VARREF_RE = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")


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


def _realpath(abspath: str) -> str:
    """Best-effort symlink resolution. realpath touches the filesystem and the
    path may not exist; never crash -- fall back to the input on any error. This
    is inherently best-effort: a symlink is only caught if it exists at analysis
    time (Evasion 3)."""
    try:
        return os.path.realpath(abspath)
    except OSError:
        return abspath


def _classify_one(abspath: str, root: str, scope_dirs: list, sensitive_patterns: list,
                  project_boundary: bool):
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


# Rank classifications so the more serious of (normalized, realpath) wins.
_KIND_RANK = {None: 0, "allowlist": 1, "boundary": 2, "sensitive": 3}


def classify(abspath: str, root: str, scope_dirs: list, sensitive_patterns: list,
             project_boundary: bool = True):
    """Return (kind, detail). kind in {'sensitive','boundary','allowlist'} or (None, None).

    Classifies against BOTH the normalized path and its os.path.realpath, so an
    in-project symlink pointing at a sensitive/out-of-project location is caught
    (Evasion 3). The more serious of the two results wins. Best-effort: the
    symlink must exist on disk at analysis time."""
    norm = _classify_one(abspath, root, scope_dirs, sensitive_patterns, project_boundary)
    real = _realpath(abspath)
    if real == abspath:
        return norm
    # Compare the realpath'd file against the realpath'd ROOT. Otherwise a project whose
    # own path contains a symlink (e.g. /tmp -> /private/tmp on macOS, or a symlinked work
    # dir) makes EVERY in-project file look out-of-bounds. Realpathing both keeps the
    # Evasion-3 catch intact: an in-project symlink pointing OUT still resolves outside the
    # real root -> boundary/sensitive.
    real_root = _realpath(root)
    via = _classify_one(real, real_root, scope_dirs, sensitive_patterns, project_boundary)
    return via if _KIND_RANK[via[0]] > _KIND_RANK[norm[0]] else norm


def _strip_env(toks: list, assigns: dict = None) -> list:
    """Skip leading `NAME=value` env-prefixes. If `assigns` is given, RECORD each
    literal assignment so a later `$NAME` reference can be expanded (Evasion 2)."""
    i = 0
    while i < len(toks) and _ENV_RE.match(toks[i]):
        if assigns is not None:
            _record_assign(toks[i], assigns)
        i += 1
    return toks[i:]


def _record_assign(tok: str, assigns: dict) -> None:
    """Record a literal `NAME=value` assignment. Only literal values (not a $var
    or substitution) are kept, so we never resolve to something unknowable."""
    name, _, value = tok.partition("=")
    if not value or value.startswith("$") or "`" in value or "$(" in value:
        return
    assigns[name] = value


def _subst_var(tok: str, assigns: dict) -> str:
    """If `tok` is a bare `$NAME`/`${NAME}` reference we have a literal for,
    return that literal; otherwise return the token unchanged."""
    m = _VARREF_RE.match(tok)
    if m and m.group(1) in assigns:
        return assigns[m.group(1)]
    return tok


def _extract_from_script(script: str) -> list:
    """Pull candidate paths out of an interpreter script body (Evasion 1). Catches
    quoted literals — including bare basenames like '.env'/'id_rsa' — and bare
    /, ~, ./ tokens. Candidates are de-duped; benign ones classify to None downstream
    and produce no offense, so over-capturing is safe."""
    out, seen = [], set()
    for m in _SCRIPT_PATH_RE.finditer(script or ""):
        p = m.group(1) or m.group(2)
        if not p or p in seen:
            continue
        # skip URLs, over-long blobs, and whitespace-bearing prose (not a path token)
        if p.startswith(_URL_PREFIXES) or len(p) > _MAX_SCRIPT_CAND or any(c.isspace() for c in p):
            continue
        # skip code/JSON fragments left by mismatched-quote pairing (e.g. `E=[(`, `,{`, `:`)
        if any(c not in _SAFE_PATH_CHARS for c in p):
            continue
        seen.add(p)
        out.append(p)
    return out


def _extract_one(command: str, assigns: dict = None, sensitive_patterns: list = None) -> list:
    if assigns is None:
        assigns = {}
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    toks = _strip_env(toks, assigns)
    if not toks:
        return []
    if toks[0].rsplit("/", 1)[-1] == "sudo" and len(toks) > 1:   # drop a sudo prefix
        toks = _strip_env(toks[1:], assigns)
    if not toks:
        return []
    binary = toks[0].rsplit("/", 1)[-1]
    out, seen_positional = [], False
    for idx, t in enumerate(toks[1:]):
        if not t:
            continue
        # Evasion 1: interpreter script body after -c/-e -- recurse one level into it.
        if binary in _INTERPRETERS and t in ("-c", "-e") and idx + 2 < len(toks):
            out.extend(_extract_from_script(toks[idx + 2]))
            continue
        if t.startswith("-") or t in _SHELL_OPS:
            continue
        t = _subst_var(t, assigns)                  # Evasion 2: $VAR -> literal
        if t.startswith(_URL_PREFIXES):
            continue
        # Reject code/JSON fragments: a real path token never contains a quote or brace.
        # These appear when a command embeds JSON/python (e.g. `python3 -c "...{'command':
        # 'rm -rf /tmp/x'}..."`) and segment-splitting leaves an unbalanced token —
        # otherwise we'd emit garbage out_of_scope evidence like  /tmp/x'},'PostToolUse'.
        if any(c in t for c in "\"'{}"):
            continue
        t = t.rstrip(",;)")                          # trailing shell punctuation abutting a path
        if not t:
            continue
        looks = t.startswith(("/", "~", "./", "../")) or t in ("..", ".")
        first_positional = not seen_positional
        seen_positional = True
        if looks or (binary in PATH_COMMANDS and first_positional):
            out.append(t)
        elif sensitive_patterns and _matches_sensitive(t, sensitive_patterns):
            # A bare relative credential file (.env, *.pem, id_rsa) handed to a command
            # we don't model (grep, base64, tar, ...) or in a non-first position would
            # otherwise be invisible. Match its basename against the sensitive set so a
            # credential access is never silently missed, whatever the command.
            out.append(t)
    return out


def extract_paths(command: str, sensitive_patterns: list = None) -> list:
    """Heuristically pull filesystem paths out of a Bash command. Handles env-var
    prefixes (`FOO=bar cat /x`), a leading sudo, and compound commands (splits on
    `| || && ;` and inspects each segment). Conservative per-segment: a token is a path
    only if it looks like one or is the first positional of a known path-command.

    Also defeats three evasions: recurses into interpreter `-c`/`-e` script bodies
    (`bash -c 'cat /etc/shadow'`), and expands literal `NAME=value` assignments so a
    later `$NAME`/`${NAME}` resolves to its path (`TARGET=/etc/shadow; cat $TARGET`).
    Assignments carry across segments of one compound command, so the assignment and
    the use may live in different segments."""
    out, seen = [], set()
    assigns = {}            # NAME=value recorded across segments (Evasion 2)
    for seg in _SEG_RE.split(command or ""):
        for p in _extract_one(seg, assigns, sensitive_patterns):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out
