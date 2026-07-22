#!/usr/bin/env python3
"""Prove iso-codegen of a refactor to ONE Flipper-FAP translation unit / function.

Why this exists: `hitag_worker_emulate_thread` is a real-time command->reply path
timed against a narrow hardware window (T_wresp 204..212 Tc). A refactor can keep
the *logic* identical yet change the *machine code* (a non-inlined call adds
push/pop latency; passing the decoder accumulators by pointer can spill them from
registers to the stack -> jitter). Neither the compiler nor the unit tests catch
that. This tool does: it compiles a candidate with the EXACT flags ufbt uses,
disassembles one function with `objdump -dr`, and reduces it to a
position-independent fingerprint (raw opcode bytes + mnemonics + operands +
relocation targets, volatile address columns stripped). Same fingerprint =>
byte-identical instructions AND identical call/data targets => timing-identical.

The fingerprint keeps relocation lines on purpose: `bl func_a` and `bl func_b`
encode to the SAME placeholder bytes in a .o, so without the R_ARM_* reloc symbol
a changed call target would slip through. -ffunction-sections puts each function
at offset 0 of its own section, so branch annotations are position-independent.

Usage:
  codegen_fp.py fp   <tu.c> [--func NAME] [--out FILE] [--show]
  codegen_fp.py cmp  <baseline.c> <candidate.c> [--func NAME]

Env / flags:
  --cdb PATH   compile_commands.json to source the exact command from
               (default: $CDB, else the Hitag working copy's .vscode one)
  --func NAME  function symbol to fingerprint (default: hitag_worker_emulate_thread)
Exit code of `cmp`: 0 = identical codegen, 1 = differs (unified diff on stdout).
"""
import sys, os, re, json, shlex, subprocess, tempfile, hashlib, argparse

DEFAULT_CDB = os.environ.get(
    "CDB",
    ".vscode/compile_commands.json", # override with CDB=/path/to/compile_commands.json
)
DEFAULT_FUNC = "hitag_worker_emulate_thread"


def _load_entry(cdb_path, tu_basename):
    db = json.load(open(cdb_path))
    for e in db:
        if os.path.basename(e["file"]) == tu_basename:
            cmd = e.get("command") or " ".join(e["arguments"])
            return shlex.split(cmd), e["directory"]
    raise SystemExit(f"no compile_commands entry for {tu_basename} in {cdb_path}")


def _objdump_for(gcc_path):
    # the toolchain objdump sits next to the gcc named in the cdb
    d, base = os.path.split(gcc_path)
    return os.path.join(d, base.replace("gcc", "objdump"))


def compile_tu(candidate_c, cdb_path, workdir, tu_name):
    """Compile candidate_c with the cdb's exact flags; return path to the .o.

    tu_name is the basename whose compile command to reuse (e.g. hitag_worker.c) —
    kept separate from candidate_c so a renamed baseline/variant still resolves the
    right flags."""
    tokens, directory = _load_entry(cdb_path, tu_name)
    out_o = os.path.join(workdir, "candidate.o")
    new = []
    skip = False
    for i, t in enumerate(tokens):
        if skip:  # this token was the -o argument, already replaced
            skip = False
            continue
        if t == "-o":
            new += ["-o", out_o]
            skip = True
        elif os.path.basename(t) == tu_name:
            new.append(os.path.abspath(candidate_c))  # swap the input .c
        else:
            new.append(t)
    if "-o" not in new:
        new += ["-o", out_o]
    r = subprocess.run(new, cwd=directory, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"compile failed for {candidate_c}")
    return out_o, _objdump_for(tokens[0])


_ADDR_DISASM = re.compile(r"^\s*[0-9a-f]+:\t")       # "  a4:\t"
_ADDR_RELOC = re.compile(r"^\s*[0-9a-f]+: (R_)")     # "  a4: R_ARM_..."


def fingerprint(candidate_c, cdb_path, func, tu_name="hitag_worker.c"):
    with tempfile.TemporaryDirectory() as wd:
        obj, objdump = compile_tu(candidate_c, cdb_path, wd, tu_name)
        dis = subprocess.run(
            [objdump, "-dr", obj], capture_output=True, text=True, check=True
        ).stdout
    lines, grab = [], False
    for ln in dis.splitlines():
        if re.match(rf"^[0-9a-f]+ <{re.escape(func)}>:$", ln):
            grab = True
            continue
        if grab:
            if ln.strip() == "":       # blank line = end of the function's section
                break
            ln = _ADDR_DISASM.sub("", ln)      # drop the volatile instruction address
            ln = _ADDR_RELOC.sub(r"\1", ln)    # drop the volatile reloc r_offset
            ln = re.sub(r"[ \t]+", " ", ln).rstrip()  # normalize whitespace
            lines.append(ln)
    if not lines:
        raise SystemExit(f"symbol {func} not found in the compiled object")
    text = "\n".join(lines) + "\n"
    return text, hashlib.sha256(text.encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser(add_help=True)
    sub = ap.add_subparsers(dest="mode", required=True)
    p1 = sub.add_parser("fp")
    p1.add_argument("tu")
    p1.add_argument("--func", default=DEFAULT_FUNC)
    p1.add_argument("--cdb", default=DEFAULT_CDB)
    p1.add_argument("--out")
    p1.add_argument("--show", action="store_true")
    p1.add_argument("--tu-name", default="hitag_worker.c",
                    help="basename whose compile command to reuse (default hitag_worker.c)")
    p2 = sub.add_parser("cmp")
    p2.add_argument("baseline")
    p2.add_argument("candidate")
    p2.add_argument("--func", default=DEFAULT_FUNC)
    p2.add_argument("--cdb", default=DEFAULT_CDB)
    p2.add_argument("--tu-name", default="hitag_worker.c",
                    help="basename whose compile command to reuse (default hitag_worker.c)")
    a = ap.parse_args()

    if a.mode == "fp":
        text, sha = fingerprint(a.tu, a.cdb, a.func, a.tu_name)
        n = text.count("\n")
        print(f"{a.func}: {n} insn/reloc lines  sha256={sha}")
        if a.out:
            open(a.out, "w").write(text)
            print(f"  fingerprint written to {a.out}")
        if a.show:
            sys.stdout.write(text)
        return

    tb, sb = fingerprint(a.baseline, a.cdb, a.func, a.tu_name)
    tc, sc = fingerprint(a.candidate, a.cdb, a.func, a.tu_name)
    print(f"baseline  {a.func}: sha256={sb}")
    print(f"candidate {a.func}: sha256={sc}")
    if sb == sc:
        print(">>> IDENTICAL codegen — refactor is timing-safe for this function.")
        sys.exit(0)
    import difflib
    print(">>> DIFFERS — machine code changed:")
    sys.stdout.writelines(
        difflib.unified_diff(
            tb.splitlines(keepends=True), tc.splitlines(keepends=True),
            fromfile="baseline", tofile="candidate",
        )
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
