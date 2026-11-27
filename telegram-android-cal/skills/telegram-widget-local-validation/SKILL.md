# Telegram widget active debugging

Use this skill to minimize, inject, trace, and deliver a Telegram widget case
on an authorized Android device and a tester-owned private chat.

## Rules

- Read the package `README.md` before running a device test.
- Use only the dedicated test bot and the tester's own private chat.
- Capture the exact target with `tools/collect_target.py` before interpreting
  an RVA, crash, or non-reproduction.
- Keep network isolation enabled for local injection unless network behavior is
  explicitly under test.
- Never carry an RVA, native-library hash, or heap-layout assumption from one
  Telegram build into another without revalidation.
- Delete server-delivered widgets after the run and rotate the shared bot token
  when collaboration ends.

## Workflow

1. Install `requirements.txt`; verify matching Frida client/server versions and
   active root on the owned device.
2. Start Telegram and save `python3 tools/collect_target.py --serial SERIAL`.
3. Reproduce the JavaScript in `harness/sbx.c` built against the exact fork.
4. Put the minimized case into `payloads/debug-template.html`.
5. Run `tools/inject_widget.py` with a unique `--expect-text` and require the
   final `passed: true` summary.
6. If engine-entry confirmation is needed, resolve `qjs_eval` in the exact
   native library and rerun with `--qjs-eval-rva`.
7. Run `tools/send_widget.py inspect --html CASE`, verify `check`, then use
   `send --confirm-own-private-chat`.
8. Reproduce in the normal Telegram UI, preserve the target report and
   sanitized runtime log, and run `delete` immediately.

## Acceptance

Local injection is proven only when the summary records a native widget create,
a backend paint record containing the expected marker, no injection error, and
a live Telegram process until controlled cleanup. Bot API success proves only
delivery; the normal UI run must independently demonstrate the target behavior.
