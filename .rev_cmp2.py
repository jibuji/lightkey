import re, subprocess

REV_OLD = "24d4f49ad49fb3167531466247f6de8b183d363d"
REV_NEW = "fb9494c77f2149e8d3ff96866e2e6ff60083cef6"

def git_show(rev, path):
    return subprocess.check_output(["git", "show", f"{rev}:{path}"], text=True, encoding="utf-8")

def norm(s): return re.sub(r'\s+', '', s)

def find_item(src, prefix_re):
    src_n = norm(src)
    m = re.search(prefix_re, src_n)
    return src_n[m.start():m.start()+400] if m else "(not found)"

old_lib = git_show(REV_OLD, "crates/lk-daemon/src/lib.rs")
new_daemon_mod = git_show(REV_NEW, "crates/lk-daemon/src/daemon/mod.rs")

# Compare Daemon struct field lists exactly
def struct_fields(src):
    n = norm(src)
    i = n.index('pubstructDaemon{')
    depth = 1; j = i + len('pubstructDaemon{'); start = j
    while depth:
        if n[j] == '{': depth += 1
        elif n[j] == '}': depth -= 1
        j += 1
    body = n[start:j-1]
    # split into fields by top-level commas
    fields = []
    depth = 0; cur = ''
    for ch in body:
        if ch in '<([': depth += 1
        if ch in '>)]': depth -= 1
        if ch == ',' and depth == 0:
            fields.append(cur); cur = ''
        else: cur += ch
    if cur.strip(): fields.append(cur)
    return [f.strip().rstrip(',') for f in fields if f.strip()]

fo = struct_fields(old_lib)
fn_ = struct_fields(new_daemon_mod)
print("OLD Daemon fields:")
for f in fo: print("  ", f)
print("NEW Daemon fields:")
for f in fn_: print("  ", f)
