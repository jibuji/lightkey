import re, subprocess

REV_OLD = "24d4f49ad49fb3167531466247f6de8b183d363d"
REV_NEW = "fb9494c77f2149e8d3ff96866e2e6ff60083cef6"

def git_show(rev, path):
    return subprocess.check_output(["git", "show", f"{rev}:{path}"], text=True, encoding="utf-8")

def norm(s): return re.sub(r'\s+', '', s)

def extract_inline_tests_body(src, header):
    """Extract body of `#[cfg(test)] mod tests { ... }` balancing braces."""
    n = norm(src)
    i = n.index(header) + len(header)
    depth = 1; start = i
    while depth:
        if n[i] == '{': depth += 1
        elif n[i] == '}': depth -= 1
        i += 1
    return n[start:i-1]

# --- sync tests ---
old_sync = git_show(REV_OLD, "crates/lk-core/src/sync.rs")
new_sync_tests = git_show(REV_NEW, "crates/lk-core/src/sync/tests.rs")
old_body = extract_inline_tests_body(old_sync, '#[cfg(test)]modtests{')
# new file: strip leading use statements? just normalize whole new file; it may have header uses identical to inline ones
new_body = norm(new_sync_tests)
print("sync tests: old len", len(old_body), "new len", len(new_body))
if old_body == new_body:
    print("sync tests IDENTICAL")
else:
    # find first divergence
    n = min(len(old_body), len(new_body))
    i = 0
    while i < n and old_body[i] == new_body[i]: i += 1
    print("first divergence at", i)
    print("OLD:", old_body[max(0,i-100):i+200])
    print("NEW:", new_body[max(0,i-100):i+200])

# --- daemon tests: old inline mod tests in lib.rs vs crates/lk-daemon/src/tests/*.rs ---
old_lib = git_show(REV_OLD, "crates/lk-daemon/src/lib.rs")
old_dbody = extract_inline_tests_body(old_lib, '#[cfg(test)]modtests{')
new_test_files = [f"crates/lk-daemon/src/tests/{m}.rs" for m in ["authz","rules","sync_race","vault_events"]]
new_mod = git_show(REV_NEW, "crates/lk-daemon/src/tests/mod.rs")
combined = norm(new_mod) + "".join(norm(git_show(REV_NEW, p)) for p in new_test_files)
print("\ndaemon tests: old len", len(old_dbody), "new combined len", len(combined))

# Compare per-function: extract #[test] fns and helper fns from both, multiset
from collections import Counter

def top_fns(body):
    """split normalized fn items at depth 0 (fn ... { ... } or ; )"""
    out = []
    for m in re.finditer(r'(?:#\[[^\]]*\])*(?:pub(?:\(crate\))?|)(?:async|unsafe|extern|const|)*fn[a-zA-Z_]', body):
        pass
    # simpler: scan for 'fn' at any position preceded by start/}; then balance
    i = 0; res = Counter()
    while True:
        m = re.search(r'(?:(#\[[^\]]*\])+)?fn([a-zA-Z_][a-zA-Z0-9_]*)', body[i:])
        if not m: break
        start = m.start()
        j = i + m.end()
        # find opening brace or semicolon
        while body[j] not in '{;': j += 1
        if body[j] == ';':
            res[body[i+start:j+1]] += 1
            i = j+1; continue
        depth = 1; j += 1; bstart = j
        while depth:
            if body[j] == '{': depth += 1
            elif body[j] == '}': depth -= 1
            j += 1
        res[body[i+start:j]] += 1
        i = j
    return res

fo = top_fns(old_dbody)
fnn = top_fns(combined)
only_old = fo - fnn
only_new = fnn - fo
print("daemon test fns only in OLD:", sum(only_old.values()))
for k in list(only_old)[:10]:
    print("  OLD:", k[:150])
print("daemon test fns only in NEW:", sum(only_new.values()))
for k in list(only_new)[:10]:
    print("  NEW:", k[:150])
