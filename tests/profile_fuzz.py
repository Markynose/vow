#!/usr/bin/env python3
"""
profile parser fuzz: random and mangled .vow profiles are run through build/vow-run and compared with an
independent python implementation of the format (written from DESIGN.md of vow-run section 13, not from profile.c).

    python3 tests/profile_fuzz.py [seed] [count]

for every profile: vow-run must not crash or hang; if the oracle says invalid it must exit 125 with a message
about the profile (not "cannot unveil"); if the oracle says valid it must exit 0, or 125 with "cannot unveil"
(a path rule the file system refused), never a profile error.
"""
import os, random, subprocess, sys, tempfile

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(root, "build", "vow-run")
HLP = os.path.join(root, "build", "hlp_static")
PROMISES = ["stdio", "rpath", "wpath", "cpath", "inet", "exec"]
PERMS = "rwxcs"

def oracle(data):
    """returns None if the profile is valid, else a reason"""
    if len(data) > 65536:
        return "large"
    if b"\0" in data:
        return "nul"
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    pledge = None
    rules = []
    for raw in lines:
        if len(raw) > 4096:
            return "long line"
        line = raw.strip(b" ")
        if line == b"" or line.startswith(b"#"):
            continue
        if any(c < 0x20 or c == 0x7f for c in line):
            return "control"
        if b"=" not in line:
            return "no ="
        name, value = line.split(b"=", 1)
        name = name.rstrip(b" ")
        value = value.lstrip(b" ")
        if name not in (b"pledge", b"unveil"):
            return "directive"
        if value == b"":
            return "no value"
        if name == b"pledge":
            if pledge is not None:
                return "second pledge"
            words = value.split(b" ")
            seen = set()
            for w in words:
                if w == b"" or w.decode("latin1") not in PROMISES or w in seen:
                    return "promise"
                seen.add(w)
            if b"exec" not in seen:
                return "exec"
            pledge = value
        else:
            if b":" not in value:
                return "no colon"
            path, perms = value.rsplit(b":", 1)
            if path == b"" or not path.startswith(b"/"):
                return "path"
            if len(path) > 1 and path.endswith(b"/"):
                return "slash"
            if len(path) > 1:
                for comp in path[1:].split(b"/"):
                    if comp in (b"", b".", b".."):
                        return "component"
            if perms == b"":
                return "perms"
            ps = set()
            for ch in perms.decode("latin1"):
                if ch not in PERMS or ch in ps:
                    return "perm letter"
                ps.add(ch)
            if "x" in ps and "r" not in ps:
                return "x needs r"
            if len(rules) == 64:
                return "too many"
            for (rp, rm) in rules:
                if rp == path:
                    return "duplicate"
            rules.append((path, ps))
    if pledge is None:
        return "no pledge"
    oracle.words = set(pledge.split(b" "))
    return None

def make_line(rng, dirs):
    k = rng.randrange(10)
    if k == 0:
        return "pledge = " + " ".join(rng.sample(PROMISES, rng.randrange(1, 7)))
    if k == 1:
        return "pledge = stdio rpath exec"
    if k == 2:
        return "# " + rng.choice(["comment", "unveil = /x:r", "\tx", ""])
    if k == 3:
        return ""
    base = rng.choice(dirs + [dirs[0] + "/sub", "/nonexistent/deep", "/", "/tmp"])
    perms = "".join(rng.sample(PERMS, rng.randrange(0, 4)))
    return "unveil = %s:%s" % (base, rng.choice([perms, "r", "rw", "rwc", "rx"]))

def mangle(rng, text):
    b = bytearray(text.encode("latin1"))
    pool = b" \t:=/.#\r\0\x01abz\xe9\xff/"
    for _ in range(rng.randrange(0, 4)):
        op = rng.randrange(3)
        if op == 0 and b:
            del b[rng.randrange(len(b))]
        elif op == 1:
            b.insert(rng.randrange(len(b) + 1), rng.choice(pool))
        elif b:
            b[rng.randrange(len(b))] = rng.choice(pool)
    return bytes(b)

def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("VOW_FUZZ_SEED", "1"))
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    rng = random.Random(seed)
    tmp = tempfile.mkdtemp(prefix="pfz.", dir=os.path.join(root, "build", "tmp"))
    dirs = []
    for n in ("d1", "d2", "d3"):
        d = os.path.join(tmp, n)
        os.makedirs(os.path.join(d, "sub"))
        dirs.append(d)
    valid = invalid = bad = 0
    for i in range(count):
        lines = [make_line(rng, dirs) for _ in range(rng.randrange(1, 7))]
        if rng.random() < 0.7:
            lines.insert(rng.randrange(len(lines) + 1), "pledge = stdio rpath exec")
        text = "\n".join(lines) + rng.choice(["\n", "", "\n\n"])
        data = mangle(rng, text) if rng.random() < 0.6 else text.encode("latin1")
        path = os.path.join(tmp, "p.vow")
        open(path, "wb").write(data)
        why = oracle(data)
        try:
            r = subprocess.run([RUN, "--profile", path, "--", HLP, "ok"], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            print("HANG", data); bad += 1; continue
        err = r.stderr.decode("latin1")
        ok = True
        if why is not None:
            invalid += 1
            ok = r.returncode == 125 and "cannot unveil" not in err and "p.vow" in err
        else:
            valid += 1
            # a program without the stdio promise is killed by its first call (the exit), which is correct
            ok = r.returncode == 0 or (r.returncode == 125 and "cannot unveil" in err) or \
                (r.returncode == -31 and b"stdio" not in oracle.words)
        if not ok:
            bad += 1
            print("DISAGREE oracle=%s status=%d stderr=%r data=%r" % (why, r.returncode, err[:200], data[:300]))
    subprocess.run(["rm", "-rf", tmp])
    print("seed %d: %d profiles (%d valid, %d invalid), %d disagreements" % (seed, count, valid, invalid, bad))
    return 1 if bad else 0

sys.exit(main())
