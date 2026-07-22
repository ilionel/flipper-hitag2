#!/usr/bin/env python3
"""
decode_scope.py - analyse the Hitag2 self-scope dump (emuscope.txt).

The FAP writes /ext/apps_data/hitag/emuscope.txt: the realized per-cell timing (us)
of our LAST emulate reply, captured in the carrier-in ISR. This tool reconstructs the
Manchester waveform from those durations so we can SEE the preamble/data0 boundary that
causes the framing shift the reader observes ((real >> 1) | 0x80000000).

It is deliberately self-calibrating: it finds the base half-bit unit from the data
(no hard-coded timing), expresses each cell as a multiple of that unit, then walks the
HIGH/LOW levels to recover the Manchester bitstream. Compare the decoded data bits to
the page we emulated (e.g. UID page0 = 12 34 56 78) and to what the reader reported.

Usage:
    python3 decode_scope.py emuscope.txt           # full analysis
    python3 decode_scope.py emuscope.txt --expect 12345678
"""
import sys
import re
from collections import Counter


def load_cells(path):
    """Read the whitespace-separated us durations from an emuscope.txt dump."""
    txt = open(path).read()
    # keep only the numbers after the header (the last non-empty line of numbers)
    nums = [int(x) for x in re.findall(r"\d+", txt.split("\n\n", 1)[-1])]
    return nums


def base_unit(cells):
    """Estimate the half-bit unit (smallest recurring duration) from the data."""
    if not cells:
        return 0
    # the modal small value is the half-bit; ignore the trailing reset cell (tiny)
    body = [c for c in cells if c > max(cells) * 0.1]
    c = Counter(body)
    # the most common duration is one half-bit (16 carrier periods ~ 128us)
    unit = min(d for d, _ in c.most_common(3))
    return unit


def quantize(cells, unit):
    """Express each cell as a rounded multiple of the half-bit unit."""
    return [round(c / unit) if unit else 0 for c in cells]


def manchester_decode(levels):
    """
    Given a list of (level, half_units) segments, decode Manchester bits.
    Hitag2 tag side (PM3 hitag_send_frame): bit 1 = HIGH-LOW, bit 0 = LOW-HIGH,
    one bit = 2 half-units. A merged 3-half segment marks a value change boundary.
    Returns the recovered bit string (best-effort) for inspection.
    """
    # flatten to a half-unit level sequence, then read pairs
    seq = []
    for lvl, n in levels:
        seq.extend([lvl] * max(1, n))
    bits = []
    i = 0
    while i + 1 < len(seq):
        a, b = seq[i], seq[i + 1]
        if a and not b:
            bits.append("1")  # HIGH-LOW
        elif (not a) and b:
            bits.append("0")  # LOW-HIGH
        else:
            bits.append("?")  # no mid transition in this window
        i += 2
    return "".join(bits)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    path = sys.argv[1]
    expect = None
    if "--expect" in sys.argv:
        expect = sys.argv[sys.argv.index("--expect") + 1].upper()

    cells = load_cells(path)
    if not cells:
        print("no cells found in", path)
        return
    unit = base_unit(cells)
    q = quantize(cells, unit)

    print(f"cells: {len(cells)}   half-bit unit ~= {unit} us "
          f"(~{unit/8:.0f} carrier periods @8us)")
    print("\nraw us   :", " ".join(str(c) for c in cells))
    print("halfunits:", " ".join(str(x) for x in q))

    # The capture alternates HIGH/LOW segments. We don't know the starting level for
    # certain, so try both and show the decode; the preamble (5 ones) should appear as
    # a run of '1's, and the first '0' (or the merged 3-unit cell) marks data start.
    for start_high in (True, False):
        levels = []
        lvl = start_high
        for n in q:
            levels.append((lvl, n))
            lvl = not lvl
        bits = manchester_decode(levels)
        print(f"\n[assume first segment {'HIGH' if start_high else 'LOW'}]")
        print("  bits:", bits)
        # locate the preamble run of 1s and split off the data
        m = re.match(r"(1+)(.*)", bits)
        if m:
            pre, data = m.group(1), m.group(2)
            print(f"  preamble 1s: {len(pre)}   data bits: {data[:40]}")
            hexbits = data.replace("?", "0")[:32]
            if len(hexbits) >= 8:
                val = int(hexbits.ljust(32, "0"), 2)
                print(f"  data[0:32] = {val:08X}")
                if expect:
                    exp = int(expect, 16)
                    print(f"  expected   = {exp:08X}   "
                          f"shifted(>>1|0x80000000) = {(exp >> 1) | 0x80000000:08X}")
    print("\nNote: compare 'data[0:32]' to the emulated page and to what the reader read.")
    print("A clean fix = data[0:32] equals the real page with preamble exactly 5.")


if __name__ == "__main__":
    main()
