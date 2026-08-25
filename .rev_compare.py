import re, subprocess, sys
from collections import Counter

REV_OLD = "24d4f49ad49fb3167531466247f6de8b183d363d"
REV_NEW = "fb9494c77f2149e8d3ff96866e2e6ff60083cef6"

def git_show(rev, path):
    return subprocess.check_output(["git", "show", f"{rev}:{path}"], text=True, encoding="utf-8")

def strip_comments(src):
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    out = []
    in_str = None
    for ln in src.split('\n'):
        i = 0; res = ''
        while i < len(ln):
            c = ln[i]
            if in_str:
                res += c
                if c == '\\' and i+1 < len(ln):
                    res += ln[i+1]; i += 2; continue
                if c == in_str: in_str = None
                i += 1; continue
            if c in '"\'':
                in_str = c; res += c; i += 1; continue
            if ln.startswith('//', i): break
            if ln.startswith('/*', i):
                # block comment within line: skip to end (rare) - handle via pre-pass already done crudely
                j = ln.find('*/', i+2)
                i = j+2 if j >= 0 else len(ln); continue
            res += c; i += 1
        out.append(res)
    return '\n'.join(out)

def norm(s): return re.sub(r'\s+', '', s)

def split_items(src):
    src = strip_comments(src)
    items = []; i = 0; n = len(src)
    while i < n:
        if src[i] in ' \t\n\r;': i += 1; continue
        start = i
        while True:
            m = re.match(r'\s*(#\[[^\]]*\]|#!\[[^\]]*\])', src[i:])
            if m: i += m.end(); continue
            i += re.match(r'\s*', src[i:]).end()
            break
        depth = 0; j = i; started = False
        while j < n:
            c = src[j]
            if c == '{': depth += 1; started = True
            elif c == '}':
                depth -= 1
                if started and depth == 0: j += 1; break
            elif c == ';' and depth == 0: j += 1; break
            j += 1
        items.append(norm(src[start:j])); i = j
    return items

def split_impl_methods(item):
    m = re.match(r'(pub(\(crate\))?|)\s*impl[^{]*\{', item)
    if not m: return [item]
    head_end = item.index('{')
    head = item[:head_end]
    body = item[head_end+1:].rsplit('}', 1)[0]
    out = [head + '{']
    depth = 0; start = None; i = 0; n = len(body)
    while i < n:
        c = body[i]
        if c == '{':
            if depth == 0: start = i
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0 and start is not None:
                out.append(norm(body[start:i+1])); start = None
        i += 1
    return out

def bag(entries):
    cnt = Counter()
    for get in entries:
        try: src = get()
        except subprocess.CalledProcessError: continue
        for it in split_items(src):
            for piece in split_impl_methods(it):
                cnt[piece] += 1
    return cnt

def compare(name, old_paths, new_paths):
    old = bag([(lambda p=p: git_show(REV_OLD, p)) for p in old_paths])
    new = bag([(lambda p=p: git_show(REV_NEW, p)) for p in new_paths])
    print(f"===== {name}: old items {sum(old.values())}, new items {sum(new.values())}")
    only_old = old - new
    only_new = new - old
    print(f"--- items only in OLD ({sum(only_old.values())}):")
    for k, v in sorted(only_old.items()):
        if len(k) > 160: k = k[:80] + ' ... ' + k[-60:]
        print(f"  x{v}: {k}")
    print(f"--- items only in NEW ({sum(only_new.values())}):")
    for k, v in sorted(only_new.items()):
        if len(k) > 160: k = k[:80] + ' ... ' + k[-60:]
        print(f"  x{v}: {k}")

compare("sync", ["crates/lk-core/src/sync.rs"],
        ["crates/lk-core/src/sync/mod.rs"] + [f"crates/lk-core/src/sync/{m}.rs" for m in ["config","engine","plan","read","tests"]])

compare("daemon-lib", ["crates/lk-daemon/src/lib.rs"],
        ["crates/lk-daemon/src/lib.rs@NEW"] and
        ["crates/lk-daemon/src/daemon/" + m + ".rs" for m in ["mod","authz","items","lifecycle","rules","session","sync_cmds","vault_cmds"]] )
