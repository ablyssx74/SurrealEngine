# Offline replay of captured UE1 actor bunches, used to work out a server's wire format.
#
# Capture: run SurrealEngine with SE_DEBUG_NET=1 SE_NET_CAPTURE=1 and keep stderr, e.g.
#   SE_DEBUG_NET=1 SE_NET_CAPTURE=1 ./SurrealEngine --autostart --url=unreal://host:7777 \
#       --engineversion=469 /path/to/UnrealTournament 2> cap.log
# Then:  python3 Tools/replay_net_capture.py cap.log
#
# Every bunch is decoded with the format assumptions in decode_value(); a bunch counts as "clean" when
# decoding ends exactly on its last bit. Change an assumption (vector bound, rotator widths, ...) and
# see how many bunches stay clean - that is how the v469 rotator width (14 bits) was found.
import sys, re, math, itertools, collections

LOG = sys.argv[1] if len(sys.argv) > 1 else "cap.log"
MAXOBJ = None

classes = {}   # name -> dict(max, fields{idx: dict})
bunches = []   # (ch, cls, open, start, total, bits)
cur = None
for line in open(LOG, errors="ignore"):
    if line.startswith("CAPCLASS "):
        _, name, mx = line.split()
        cur = {"max": int(mx), "fields": {}}
        classes[name] = cur
    elif line.startswith("CAPFIELD "):
        p = line.split()
        idx = int(p[1]); kind = p[2]
        cur["fields"][idx] = {"kind": kind, "name": p[3], "vt": p[4], "enumN": int(p[5]), "dim": int(p[6]), "params": []}
    elif line.startswith("CAPPARAM "):
        p = line.split()
        idx = int(p[1])
        cur["fields"][idx]["params"].append({"name": p[3], "vt": p[4], "enumN": int(p[5]), "dim": int(p[6])})
    elif line.startswith("CAPBUNCH "):
        p = line.split()
        bunches.append((int(p[1]), p[2], int(p[3]), int(p[4]), int(p[5]), p[6] if len(p) > 6 else ""))
    else:
        m = re.search(r"static object ref index=\d+/(\d+)", line)
        if m and MAXOBJ is None:
            MAXOBJ = int(m.group(1))

class Err(Exception):
    pass

class BR:
    def __init__(self, bits, pos):
        self.b = bits; self.p = pos
    def rem(self): return len(self.b) - self.p
    def bit(self):
        if self.p >= len(self.b): raise Err()
        v = self.b[self.p] == "1"; self.p += 1; return int(v)
    def bits_(self, n):
        v = 0
        for i in range(n): v |= self.bit() << i
        return v
    def int_(self, mx):
        v = 0; mask = 1
        while v + mask < mx and mask:
            if self.bit(): v |= mask
            mask <<= 1
        return v

def ceillog2(n):
    return (n - 1).bit_length() if n > 1 else 0

def decode_value(br, vt, enumN, V):
    if vt == "Byte":
        n = max(1, math.ceil(math.log2(max(2, enumN)))) if enumN else 8
        return br.bits_(n)
    if vt in ("Int", "Float"):
        return br.bits_(32)
    if vt == "Bool":
        return br.bit()
    if vt == "Object":
        if br.bit():
            return br.int_(1023)
        return br.int_(MAXOBJ)
    if vt == "Vector":
        bits = br.int_(V["vecB"])
        bias = 1 << (bits + 1); mx = 1 << (bits + 2)
        for _ in range(3): br.int_(mx)
        return 0
    if vt == "Rotator":
        for _ in range(3):
            if br.bit(): br.bits_(V.get("rotBits", 14))   # 14 on v469; the byte-per-axis form (8) is v436
        return 0
    if vt == "Color":
        if V.get("color", True): br.bits_(32)
        else: raise Err()
        return 0
    raise Err()  # unsupported

def run(V, verbose=False):
    clean = 0; results = []
    for (ch, cls, op, start, total, bits) in bunches:
        C = classes.get(cls)
        if not C: continue
        br = BR(bits, start)
        ok = False; stop = "?"
        trail = []
        try:
            while True:
                remain_before = br.rem()
                idx = br.int_(C["max"])
                f = C["fields"].get(idx)
                if not f or f["kind"] == "X":
                    stop = "badidx"; break
                if f["kind"] == "P":
                    if f["dim"] != 1: br.bits_(8)
                    decode_value(br, f["vt"], f["enumN"], V)
                    trail.append(f["name"])
                else:
                    for prm in f["params"]:
                        if prm["vt"] == "Bool": present = 1
                        else: present = br.bit()
                        if present: decode_value(br, prm["vt"], prm["enumN"], V)
                    trail.append(f["name"] + "()")
        except Err:
            stop = "end" if remain_before == 0 else ("unsupported/short@%d" % remain_before)
            ok = (remain_before == 0)
        if ok: clean += 1
        results.append((ch, cls, ok, stop, trail))
    return clean, results

if __name__ == "__main__":
    print("bunches", len(bunches), "classes", len(classes), "MAXOBJ", MAXOBJ)
    for rotBits in (8, 14):
        c, _ = run({"vecB": 16, "rotBits": rotBits})
        print("rotator axis bits", rotBits, "-> clean bunches", c)
