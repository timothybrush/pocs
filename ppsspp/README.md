# PPSSPP Guest-to-Host RCE

These vulnerabilities were discovered with [V12](https://v12.sh) by Nihal Talur
of the [V12 security team](https://x.com/v12sec).

## Abstract

This PoC is a single animated PSP ISO that chains two memory-safety bugs in
PPSSPP's high-level emulation and opens Calculator on the Windows host:

- a crafted MPEG decode exposes host heap data to the emulated PSP, leaking
  object pointers and defeating ASLR;
- an out-of-bounds Atrac stream-data update replaces a host virtual call target
  with a rebased ROP chain.

**Impact: full guest-to-host escape.** A malicious PSP game can execute native
code with the privileges of the PPSSPP process.

The exploit targets the official **PPSSPP v1.20.4 Windows x64** build with ASLR
and DEP enabled. It is build-specific; other revisions or platforms will
normally crash or show the failure screen instead of opening Calculator. The
pinned `PPSSPPWindows64.exe` SHA-256 is:

```text
775a0ded7d0c0602f46c3aeed659228d629e98ed77d9e2bd3818c44eb30de85a
```

## Build

Requirements are Python 3 and Docker. The build uses the official
`pspdev/pspdev:latest` image and has no host PSP SDK requirement.

```bash
python3 build.py
# output: v12.iso
```

The normal build uses checked-in media and logo data. To regenerate
`rom/logo_data.h`, install Pillow, run `python3 tools/gen_fancy.py`, then rerun
`build.py`.

## Run

```powershell
PPSSPPWindows64.exe v12.iso
```

The ISO displays the V12 animation, recovers PPSSPP's randomized image base,
constructs a target-specific Win64 chain, and invokes PPSSPP's existing
`ShellExecuteA` wrapper with the `calculator:` URI.

> This is a guest-to-host code-execution PoC. Run it only in a disposable
> environment that you control.

## How It Works

1. The guest initializes MPEG with `rom/craft.pmf` and requests crafted AVC
   decodes whose output includes adjacent host heap data.
2. It scans the guest-visible output for Atrac and PSP thread object layouts,
   recovering an Atrac data-buffer pointer and a PSP thread vtable pointer.
3. The vtable pointer is converted to the randomized PPSSPP image base using
   the module-relative offsets in `rom/exploit.h`.
4. Repeated thread and Atrac allocations groom a victim host object next to a
   guest-controlled stream buffer.
5. A crafted RIFF loop layout positions the Atrac stream write, and an
   out-of-bounds eight-byte update redirects the victim vtable to a ROP chain in
   that buffer.
6. The chain pivots the stack, supplies the `calculator:` URI, calls the pinned
   `ShellExecuteA` wrapper, and parks the corrupted thread.

The checked-in `v12.iso` is built from the same files used by `build.py`; `out/`
contains only disposable compiler intermediates.
