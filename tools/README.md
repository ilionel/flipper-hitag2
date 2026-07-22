# tools/

Off-device developer tools. Neither ships in the FAP.

## `codegen_fp.py` — prove a change didn't move the timing-critical machine code

`hitag_worker_emulate_thread` is a real-time command→reply path timed against a narrow
hardware window (T_wresp 204..212 Tc). A change can keep the *logic* identical yet shift
the *machine code* — a non-inlined call adds push/pop latency; passing the decoder
accumulators by pointer can spill them from registers to the stack (jitter). Neither the
compiler nor the unit tests catch that; this does.

It compiles a candidate `hitag_worker.c` with the **exact** flags ufbt used (read from a
`compile_commands.json`), disassembles one function with `objdump -dr`, and reduces it to a
position-independent fingerprint: raw opcode bytes + mnemonics + operands + **relocation
targets** (so a changed call target can't hide behind identical placeholder bytes), with the
volatile address columns stripped. Same fingerprint ⇒ byte-identical instructions and
identical call/data targets ⇒ **timing-identical**.

Prereq: a built, patched-SDK ufbt project so a `compile_commands.json` exists
(`ufbt` generates the `.vscode/compile_commands.json`). Point `--cdb` at it, or set `$CDB`.

### Use 1 — refactor guard (same SDK, two source variants)

Before keeping ANY edit to `hitag_worker_emulate_thread` (or another function via `--func`):

```bash
cp hitag_worker.c /tmp/baseline.c          # freeze the pre-edit source
# ... make the edit ...
python3 tools/codegen_fp.py cmp /tmp/baseline.c hitag_worker.c
#   exit 0  -> IDENTICAL codegen, the edit is timing-safe -> keep it
#   exit 1  -> machine code changed (unified diff shown) -> revert, or re-bench before keeping
```

Empirical result on this function: no helper extraction of `emulate_thread` comes out
byte-identical — GCC allocates it as one register arena, so any helper boundary reshuffles
allocation across the whole function (the diffs are *balanced* — same instruction mix, likely
iso-cycle — but not iso-bytes). That is why the function is kept monolithic; comments/docs are
codegen-neutral (proven: adding the phase map above scored exit 0), refactors are not.

Caveat when reading a non-identical `cmp` diff: `furi_check` / `furi_crash` expand to
uniquely-named local symbols (`sukimaNNNN` on Momentum). objdump then annotates nearby
literal-pool loads relative to those symbols, so a function that gained/lost a `furi_check`
shows a large diff dominated by changed `<sym+0x..>` annotations and shifted `[pc, #N]`
offsets — same instructions, not a real change. Read the instruction bytes/mnemonics, not the
annotations. The exit-0 identity check is unaffected (two identical compiles emit identical
symbols).

### Use 2 — rebase regression check (same source, two SDKs)

When rebasing the RTF HAL patch onto a new Momentum SDK, prove the SDK/toolchain bump did not
silently change the timing-critical codegen. Fingerprint the same source under each SDK's
`compile_commands.json` and diff:

```bash
python3 tools/codegen_fp.py fp hitag_worker.c --cdb /path/OLD-sdk/.vscode/compile_commands.json --out /tmp/before.fp
python3 tools/codegen_fp.py fp hitag_worker.c --cdb /path/NEW-sdk/.vscode/compile_commands.json --out /tmp/after.fp
diff /tmp/before.fp /tmp/after.fp && echo "SDK bump is codegen-neutral for emulate_thread"
```

A non-empty diff means the new toolchain/headers changed the emitted code — re-bench the
emulate reply timing against a real reader before trusting the rebase.

### Options
- `--func NAME`   function symbol to fingerprint (default `hitag_worker_emulate_thread`)
- `--cdb PATH`    `compile_commands.json` to source the exact command from (default `$CDB`)
- `--tu-name`     basename whose compile command to reuse (default `hitag_worker.c`) — lets a
                  renamed baseline still resolve the right flags
- `fp --show`     print the normalized fingerprint; `fp --out FILE` writes it

## `decode_scope.py` — off-device decode of the emulate self-scope

Reconstructs the Manchester waveform from an `emuscope_*.txt` cell dump (the realized per-cell
timing of the last emulate reply) to inspect the preamble/data boundary. See its `--help`.
