# cups2root

## Abstract

This PoC chains CUPS configuration and privilege-boundary flaws to open an
interactive root shell from a local account in the `lpadmin` group:

- the privileged serial backend can overwrite `/etc/cups/cups-files.conf`;
- a malformed IPP request crash-restarts CUPS with an attacker-controlled
  `ServerBin` directory;
- the restarted daemon executes a replacement `cups-exec` as root.

The exploit preserves the original configuration, supports AMD64 and ARM64,
and removes its queue and local artifacts after the root shell exits.

## Exploitation

Run the PoC as a local user whose supplementary groups include `lpadmin` and
whose primary group is neither `lpadmin`, `root`, nor a configured CUPS
`SystemGroup`:

```bash
python3 cups2root.py
```

The target must use systemd, have an active local CUPS service and serial
backend, and provide the standard Ubuntu CUPS paths used by the exploit. No
third-party Python dependencies are required.

After exploitation succeeds, the PoC opens an interactive root shell. Exit the
shell to let it remove the temporary setuid shell and other artifacts.

## How It Works

1. The PoC creates a raw serial printer whose device URI points at
   `/etc/cups/cups-files.conf`. Because the serial backend runs as root, print
   data replaces the configuration from the backend's 2,048-byte offset.
2. It injects the caller's primary group as CUPS `Group` and redirects
   `RequestRoot`, `ServerRoot`, `TempDir`, and `ServerBin` to
   `/etc/cups/interfaces`.
3. A malformed IPP subscription request crashes CUPS. systemd restarts it with
   the modified configuration, making `/etc/cups/interfaces` writable by the
   caller's primary group and treating it as `ServerBin`.
4. The PoC stages a replacement `cups-exec` and triggers a CGI request. CUPS
   invokes the replacement as root, which installs an embedded setuid shell,
   restores the original configuration, and restores the genuine
   `/usr/lib/cups/daemon/cups-exec`.
5. After verifying the restored service and privileged shell, the PoC opens the
   root shell and cleans up when it exits.

## Credit

These vulnerabilities were discovered with [V12](https://v12.sh) by Rick de
Jager of the [V12 security team](https://x.com/v12sec).

> Want to find issues like this in your own code? Try V12 at
> [v12.sh](https://v12.sh).
