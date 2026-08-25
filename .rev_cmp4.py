import re, subprocess

REV_OLD = "24d4f49ad49fb3167531466247f6de8b183d363d"
REV_NEW = "fb9494c77f2149e8d3ff96866e2e6ff60083cef6"

def git_show(rev, path):
    return subprocess.check_output(["git", "show", f"{rev}:{path}"], text=True, encoding="utf-8")

def norm(s): return re.sub(r'\s+', '', s)

def extract_inline_tests_body(src, header):
    n = norm(src)
    i = n.index(header) + len(header)
    depth = 1; start = i
    while depth:
        if n[i] == '{': depth += 1
        elif n[i] == '}': depth -= 1
        i += 1
    return n[start:i-1]

# --- sync tests: compare after skipping leading use statements ---
old_sync = git_show(REV_OLD, "crates/lk-core/src/sync.rs")
new_sync_tests = git_show(REV_NEW, "crates/lk-core/src/sync/tests.rs")
old_body = extract_inline_tests_body(old_sync, '#[cfg(test)]modtests{')
new_body = norm(new_sync_tests)

def skip_uses(s):
    while s.startswith('use'):
        # find terminating ; at depth 0 of braces
        depth = 0; j = 0
        for j in range(len(s)):
            if s[j] == '{': depth += 1
            elif s[j] == '}': depth -= 1
            elif s[j] == ';' and depth <= 0: break
        s = s[j+1:]
    return s

o = skip_uses(old_body); nn = skip_uses(new_body)
print("after uses: old", len(o), "new", len(nn))
if o == nn: print("sync test bodies IDENTICAL")
else:
    n = min(len(o), len(nn)); i = 0
    while i < n and o[i] == nn[i]: i += 1
    print("divergence at", i)
    print("OLD:", o[max(0,i-120):i+250])
    print("NEW:", nn[max(0,i-120):i+250])

# --- daemon: full diff of that put() fn ---
old_lib = git_show(REV_OLD, "crates/lk-daemon/src/lib.rs")
old_dbody = extract_inline_tests_body(old_lib, '#[cfg(test)]modtests{')
i = old_dbody.find('fnput(&self')
print("\nOLD put fn:", old_dbody[i:i+400])
j = None
for p in ["authz","rules","sync_race","vault_events"]:
    src = git_show(REV_NEW, f"crates/lk-daemon/src/tests/{p}.rs")
    k = src.find('fnput(&self')
    if k >= 0:
        print(f"\nNEW put fn ({p}):", norm(src)[k:k+400])
