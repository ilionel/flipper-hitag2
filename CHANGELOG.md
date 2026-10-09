# Changelog

## Unreleased
- **CI.** A GitHub Actions workflow now builds and runs the off-device unit tests
  (frame classifier, CRC-8, Hitag2 cipher) with warnings-as-errors on every push and
  pull request — no Flipper SDK needed, so regressions in those critical pure modules
  fail the build.
- **Internal cleanup (no behaviour change).** The 32-bit page byte-split repeated across
  the read/sniff paths is now a single `hitag_store_page()` helper (6 call sites), and the
  two command-log writers share one scratch buffer instead of a per-function copy
  (−1.25 KB BSS). Fixed a few stale comments (emulate preamble default, autotune log header).

## 1.6
- **Persistent settings.** The keys/passwords (Hitag2 password, Hitag S key, 82xx pwd),
  the emulate tuning (Mode / Timing / `T_wresp`) and the Debug toggles now survive a
  reboot — saved to `apps_data/hitag/settings.conf` on exit, restored at startup.
- **Settings → Reset to defaults** restores every setting to its factory value and saves
  immediately (loaded dumps are left untouched).

## 1.5
- **Internal refactor (no behaviour change).** The two monolith source files were split
  by concern for readability: the worker is now `hitag_worker.c` (shared emulate thread +
  decoder + DMA) plus per-protocol `hitag1.c` / `hitag2.c` / `hitags.c`, and the UI is
  `hitag_app.c` + `hitag_menu.c`, each behind an internal `*_i.h` header. The vestigial
  `lfrfid_` prefix (a leftover of the app's origin inside the firmware's lfrfid app) was
  dropped. Dead code from earlier UI iterations was removed. See the project layout in
  [REFERENCE §8](docs/REFERENCE.md). The emulate/timing path is byte-for-byte unchanged.

## 1.4
- **Sniff → Hitag2 crypto:** passively collects the reader's `nR/aR` auth nonces and writes
  them to `nonces_<uid>_<ts>.txt`, ready for the PC-side `hitag2crack` tools. The Flipper is
  the collector (like the Proxmark3 ARM); on-device key recovery isn't feasible — see
  REFERENCE §6.
- **Sniff → Hitag S 82xx:** passively captures the 4-byte 8268/8310 password the reader
  writes to virtual page 64 (CRC-checked) and applies it to **Settings → Hitag S 82xx pwd**.
- The Sniff menu is now **Hitag2 password · Hitag2 crypto · Hitag S 82xx**; the live sniff
  screen shows a per-target tally (nonces captured / 82xx pending).
- Frame-decode is routed by sniff target (reuses the crypto / Hitag S validators); the
  Hitag2-password sniff and the emulate paths are unchanged. Off-device tests now also cover
  the WRITE(page 64) 82xx trigger (48 total).

## 1.3
- **NFC-style card model:** after a Read / Sniff, or opening a **Saved** dump, you now
  land on a per-card action menu (**Info · Emulate · Save**, plus **Rename · Delete**
  for a saved file) — the same flow as the NFC app, instead of a single content view.
- **Dumps → Saved:** the top menu entry is now **Saved** and opens the `.hitag` browser
  directly; Save / Rename / Delete moved onto the card menu.
- **Emulate mirrors Read:** both list the protocols in NXP release order
  (**Hitag1 → Hitag2 → Hitag S**); **Emulate → Hitag2** auto-selects password vs crypto
  from the dump's config page (no separate "HT2 crypto" entry).
- **Card → Emulate** emulates each dump in its own family, and **Info**'s `OK` emulates
  the shown card.

## 1.2
- **UX:** the menu is reorganised NFC-style into a few top-level groups
  (Read / Sniff / Emulate / Dumps / Settings / Debug), each opening a focused
  list; Back walks one level up. The three Emulate entries now live under
  **Emulate**, the keys/passwords under **Settings**, and diagnostic recording
  under **Debug → Traces**.
- **Coupling hint:** the Emulate screen shows *"Move to find coupling"* while
  nothing is coming through (AUTH = 0), and Sniff shows *"Move into reader
  field"* until the first command — LF coupling is position-sensitive.
- Refreshed screenshots.

## 1.1
- **Hitag S** support: full tag **emulation** (`UID_REQ → SELECT → READ / WRITE`)
  across all four reader modes (Standard / Advanced ×2 / Fast-Advanced), plus
  **crypto/challenge** (`--crypto` / `--nrar`), **8268/8310 password** (`--82xx`),
  and config **lock bits** (LKP / LCON / LCKn). A `Read Hitag S` (UID + SELECT) is
  included (coupling-limited).
- **Hitag2 crypto mode** emulation: `nRaR` mutual authentication with a small port
  of the 48-bit Hitag2 stream cipher, then encrypted page reads (`Emulate HT2
  crypto`), separate from the proven password `Emulate`.
- **Reply-framing corrected**: preamble = the reader's start-of-frame length with
  **no leadbit** now reads back all 32 bits faithfully (the old leadbit/pre-shift
  dropped bit 31 — e.g. `0xAA` → `0x2A`). This is what makes crypto reads and
  MSB-set pages work; validated on a Proxmark3.
- **Detect** now rotates Hitag2 → Hitag1 → Hitag S.
- **Editable keys**: menu entries for the Hitag S crypto key and the 82xx password
  (no dump editing needed).
- **Debug traces** toggle (Emulation settings): diagnostic files are now **off by
  default** — nothing is written unless you enable it.
- Off-device tests now also cover the CRC-8 and the cipher keystream (cross-checked
  against the Proxmark3 reference).

## 1.0
- First public release: Hitag2 (125 kHz LF) **read**, **sniff**, and **tag
  emulation** in password mode for the Flipper Zero, plus basic Hitag1.
- **Reply-framing fix** (leadbit + pre-shift): an emulated Hitag2 UID now reads
  back byte-for-byte on a real reader (verified with a Proxmark3).
- **Emulate** with a live coupling readout (AUTH / PWD / READ).
- **Emulation settings**: Mode (Normal / Tolerant), Timing (Fixed / Auto
  `T_wresp` autotune), `T_wresp`, Lean logs. *Tolerant* answers the config page
  on any 32-bit frame (for readers whose password frame is mis-decoded under
  marginal coupling); *Auto* sweeps the reply timing and locks on a hit.
- Reader-frame classifier is a pure module with off-device unit tests.
- Requires the RTF HAL firmware patch under `firmware/`.
