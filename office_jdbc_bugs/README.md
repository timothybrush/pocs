# Office JDBC Classpath Bugs

LibreOffice Calc and Apache OpenOffice Calc can silently load attacker-controlled
Java bytecode when a malicious spreadsheet auto-refreshes a database range from
a remote ODB whose JDBC classpath points to a remote JAR.

- [LibreOffice PoC](libreoffice/README.md) — [CVE-2026-63277](https://www.libreoffice.org/security/), fixed in LibreOffice 26.2.5 and 26.8.0.
- [Apache OpenOffice PoC](openoffice/README.md) — [CVE-2026-59265](https://nvd.nist.gov/vuln/detail/CVE-2026-59265), affecting 4.1.16 and earlier and expected to be fixed in 4.1.17.
