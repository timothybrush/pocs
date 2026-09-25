# Ghostscript -dSAFER Sandbox Bypass and Command Execution via Shading Type 5 Out-of-Bounds Write

## Summary

A crafted PostScript program can make Ghostscript execute an attacker-chosen
shell command while running under the `-dSAFER` sandbox. The program never
references an external file and never depends on a fixed address; it builds its
own memory read/write primitives at run time, defeats ASLR from inside the
interpreter, locates the SAFER path-control state, disables it, and then uses
ordinary PostScript pipe support to launch the command.

The exploit composes two memory-safety bugs that are reachable from pure
PostScript under `-dSAFER`:

1. A procedure-source filter stream **use-after-free** (`psi/zfproc.c`) that
   discloses heap memory. This is used as the information leak that defeats
   ASLR.
2. A shading `/Function` array **out-of-bounds heap write**
   (`base/gsshade.c`, `psi/zshade.c`, `base/gsfunc3.c`) that writes
   attacker-controlled values past a color buffer. This is used as the write
   primitive.

Together they yield arbitrary read and arbitrary write inside the Ghostscript
process, which the program turns into a sandbox escape and command execution.

## Impact

Rendering a malicious PostScript/EPS document with `-dSAFER` enabled executes
attacker-controlled shell commands in the Ghostscript process context. `-dSAFER`
is the sandbox that is supposed to make rendering untrusted documents safe, so
this is a full bypass of the security boundary, not merely a crash.

Ghostscript is reached automatically by many pipelines that process untrusted
input: print/spooling systems, ImageMagick and other image converters that
delegate PostScript/EPS/PDF to Ghostscript, document-thumbnailing services, and
office suites that import EPS images. In those settings the document author, not
the operator, chooses the command that runs.

The proof of concept runs `id` and writes its output to a file. The underlying
primitive is arbitrary command execution; the demonstration command is
incidental.

## Vulnerability Details

### Bug 1 — Procedure-source filter stream use-after-free (information leak)

`psi/zfproc.c` implements a stream whose data source is a PostScript procedure.
The state-init and read paths (`s_proc_init`, `s_proc_read_process`,
`s_proc_read_continue`) store the procedure's returned string into the stream
state with a raw C assignment:

```c
ss->data = *opbuf;        /* no store_check_space, no alloc_save_change */
```

There is no save/restore write barrier on this assignment. A procedure stream
created with `currentglobal` true can hold a reference to a string allocated in
local VM. A surrounding `save`/`restore` frees the local string but never
reverts `ss->data`, so the global stream state is left pointing at freed VM. The
next read `memcpy`s from the freed buffer, disclosing whatever now occupies it.

The PoC reoccupies the freed region with arrays of PostScript references and
reads them back, which leaks both a code pointer (a PIE operator address, which
defeats text-segment ASLR) and live heap pointers.

### Bug 2 — Shading `/Function` array hides output count (out-of-bounds write)

A shading dictionary's `/Function` may be a single function or an array of
functions. `base/gsshade.c:check_CBFD` validates the number of output
components, but for an array `/Function` it checks only the wrapping
`gs_function_AdOt` count `n`, which it sets to the array length. Wrapping a
sub-function that really produces many outputs in a one-element array makes the
wrapper report `n = 1` and pass the check:

```text
single  /Function << ... /C0 <N floats> ... >>   -> rangecheck (rejected)
array   /Function [ << ... /C0 <N floats> ... >> ] -> accepted (n reported as 1)
```

At evaluation time, `base/gsfunc3.c:fn_AdOt_evaluate` de-aggregates the array
and writes each sub-function's *real* output count (`len(C0)`) into the output
buffer at `out + i`, overrunning the small color slot allocated for the declared
component count. The write is attacker-controlled in value (each 4-byte float
comes from `C0`), attacker-controlled in length (array/colorspace sizing), and
forward-linear. It lands in the C heap that also holds streams, devices, and
other function-pointer-bearing objects.

### The chain

The PoC uses ShadingType 5 (a free-form Gouraud triangle mesh) to place the
overflow precisely, and proceeds entirely at run time with no hardcoded
addresses:

```text
1. zfproc UAF leak
   -> spray the freed procedure-stream string with ref arrays
   -> read them back through the stale stream
   -> recover a PIE operator pointer (text ASLR) and live heap pointers

2. Forge a write primitive
   -> the Type 5 shading overflow writes attacker words at a chosen
      offset past the color buffer (do_write)

3. Promote to arbitrary read
   -> overwrite a victim SubFileDecode stream's read cursor (r.ptr / r.limit)
      to point at any address, then readstring reads it back (readmem)

4. Walk live structures with arbitrary read (no fixed offsets)
   victim stream
     -> gs_memory_t (memory object)
     -> scan for gs_lib_ctx_t (a run of allocator function pointers
        followed by a heap pointer)
     -> scan for gs_lib_ctx_core_t
     -> scan for path_control_active (the active flag, followed by the three
        gs_path_control_set_t records and a non-null filesystem-list pointer)

5. Disable SAFER
   -> shading write flips path_control_active to 0, preserving the
      adjacent word that shares the two-word write

6. Execute
   -> %pipe%<command> (w) file closefile  runs the shell command
```

Steps 4 and 5 use structural memory scans rather than fixed field offsets, which
is why the same program works across builds without per-version offset tables.

Relevant source areas:

```text
psi/zfproc.c        s_proc_init, s_proc_read_process, s_proc_read_continue
base/gsshade.c      check_CBFD
psi/zshade.c        build_shading_function (array branch)
base/gsfunc3.c      fn_AdOt_evaluate
base/gsmemory.c     gs_memory_t / gs_lib_ctx_t / gs_lib_ctx_core_t layout
psi/zfile.c         %pipe% device handling gated by path_control_active
```

## Proof of Concept Files

The submission directory is organized as follows:

```text
.
|-- README.md
|-- REPORT.md
|-- build_payload.py
|-- package_payloads.py
`-- payloads/
    |-- poc.ps                generated core PostScript exploit
    |-- payload.eps           EPS wrapper (office suites, ImageMagick)
    |-- payload.ept           EPT (DOS EPS preview header)
    |-- payload.odt           ODF text document embedding the EPS
    |-- payload.docx          OOXML document embedding the EPS
    `-- ...                   other generated delivery sinks
```

`build_payload.py` generates the core PostScript exploit. It is fully
self-contained (Python standard library only) and embeds the exploit template
and the ABI/layout constants for the target build. `--cmd` sets the command and
`-o` sets the output path; `--trace-stages` emits coarse stage markers for
debugging the heap groom. Retargeting another build is done by editing the
`layout` dict in the script.

`package_payloads.py` wraps the exact same PostScript in the container and
extension formats used by Ghostscript front ends: raw PostScript, EPS (and its
`epsf`/`epsi`/`epi` suffixes), EPT, newline-shifted `.pdf` for ImageMagick
extension routing, SVG coder-prefix bundles, and ODF/OOXML office documents that
embed the EPS as an image. It imports `build_payload.py` to obtain the
PostScript, so the two scripts never diverge. `package_payloads.py all`
regenerates every sink at once.

`payloads/` holds the generated files. They are regenerated by the two scripts
and are safe to delete.

## Reproduction

The reproduction requires a Ghostscript build with a standard raster device. The
shading decomposition that carries the write primitive is elided on
`nullpage`/`bbox`/`pdfwrite`, so the PoC must be rendered to a raster device such
as `pbmraw`, `ppmraw`, or `pnggray`.

1. Generate the core PostScript exploit:

   ```bash
   python3 build_payload.py --cmd 'id>/tmp/gs_proof'
   ```

2. Remove any stale proof file and render the exploit under `-dSAFER`:

   ```bash
   rm -f /tmp/gs_proof
   gs -q -dSAFER -dBATCH -dNOPAUSE -sDEVICE=pbmraw -r10 -g60x60 -o /dev/null payloads/poc.ps
   ```

3. Observe that the command ran inside the sandboxed process:

   ```bash
   cat /tmp/gs_proof
   ```

   ```text
   uid=1000(user) gid=1000(user) groups=1000(user),...
   ```

The proof file is created even though Ghostscript may exit with a non-zero
status after the command runs: the command executes from inside the rendering
process before any later cleanup. To exercise a delivery sink instead, generate
it with `package_payloads.py` and render the produced file the same way, for
example `payloads/payload.eps`.

## Expected Security Behavior

Rendering a document under `-dSAFER` should not let document-controlled content
reach file or process operations that the sandbox is meant to forbid. Memory
corruption inside the interpreter should not be reachable from pure PostScript,
and the SAFER path-control state should not be modifiable by the document being
rendered.

The fixes are at the source of each bug:

- `psi/zfproc.c`: route `ss->data = *opbuf` through the store barrier
  (`ref_save`/space check) or copy the returned string into the stream state's
  own VM space; never alias a string from a different VM space.
- `base/gsshade.c` / `psi/zshade.c`: for an array `/Function`, validate the sum
  of the sub-functions' output counts against the colorspace component count,
  not the `AdOt` wrapper `n`.

## Tested Versions

Confirmed on:

```text
Linux:
  Ghostscript 10.02.1 (Ubuntu package ghostscript 10.02.1~dfsg1-0ubuntu7.8)
  Ubuntu 24.04.4 LTS x86_64
  Rendered with: gs -q -dSAFER -dBATCH -dNOPAUSE -sDEVICE=pbmraw -r10 -g60x60 -o /dev/null
  Result: command executed (8/8 runs), /tmp/gs_proof created
```

The two underlying bugs were located in GhostPDL 10.08.0 source and confirmed
present at identical source lines; behavioral validation ran on the 10.02.1
system build. The exploit's ABI/layout constants target 10.02.1 on x86-64
Linux; other builds are retargeted by editing the `layout` dict in
`build_payload.py`.
