# Firmware RTF HAL patch

`rtf-hal.patch` adds the **reader-talks-first (RTF)** HAL that this FAP needs:
DMA-driven `CARRIER_OUT` / `CARRIER_IN` on TIM1/TIM2, the `pull_out` load-mod
path for tag emulation, reply timing, and a small self-scope ring for
diagnostics. It touches only:

- `targets/f7/furi_hal/furi_hal_rfid.c`
- `targets/f7/furi_hal/furi_hal_rfid.h`
- `targets/f7/api_symbols.csv` (exports the new symbols to the app SDK)

## Tested on

- **Momentum firmware** (`mntm-dev`), API **87.6**, around commit `17af2c0`
  (patch generated against base `e1784e7`).
- Flipper Zero, f7 target.

Other bases / firmwares (Unleashed, RogueMaster, stock) are **untested**. The
delta is small and additive, so it usually rebases cleanly, but see the size
caveat below.

## ⚠️ Flash-size / stack caveat (important on newer/larger firmware)

This patch **grows the firmware binary**. On the Flipper's f7, the firmware
must fit **below the BLE radio stack** in flash (the ceiling is around
`0x080D7000` for the BLE-light stack). Momentum is already close to that ceiling,
so on a **newer or larger base** the added RTF HAL code can push the firmware
**past the limit** — in which case:

- the build may succeed but the **updater refuses to flash** (or silently
  reverts on the device, because the new firmware would overlap the radio stack), or
- `./fbt` reports a region-overflow / size error at link time.

If you hit this when rebasing onto a newer release, you must **free equivalent
flash** first — e.g. drop unused built-in apps/assets, or build a slimmer target
— before the patched firmware will flash. There is no way to keep both the full
stock feature set *and* this HAL if the base is already at the ceiling. The
tested `17af2c0` base above is known to fit.

## Apply

The patch is generated against **Momentum firmware** at base commit
[`e1784e7`](https://github.com/Next-Flip/Momentum-Firmware) (adjust the base if
you rebase onto a newer release — the delta is small and self-contained).

```bash
git clone --recursive https://github.com/Next-Flip/Momentum-Firmware.git
cd Momentum-Firmware
git checkout e1784e7          # or your target release
git apply --3way /path/to/firmware/rtf-hal.patch

# build + flash
./fbt flash_usb               # or: ./fbt updater_package  then install via qFlipper
```

If `git apply` reports conflicts on a newer base, apply by hand: the changes are
additive (new `furi_hal_rfid_rtf_*` functions + their `api_symbols.csv` lines).
When you bump `api_symbols.csv`, also bump the API minor version as usual.

## Build the FAP against the patched SDK

Either drop this project into `applications_user/hitag/` and run
`./fbt fap_hitag` from the firmware tree, or point `ufbt` at the patched SDK:

```bash
UFBT_HOME=/path/to/patched-sdk ufbt build
```

A stock SDK will fail with `implicit declaration of function
'furi_hal_rfid_rtf_*'` — that is the missing HAL this patch provides.
