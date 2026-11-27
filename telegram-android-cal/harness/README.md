# Local engine harness

`sbx.c` recreates the important widget-sandbox limits while using the QuickJS
checkout supplied by the tester. Build it against the exact Telegram fork under
test; do not substitute upstream QuickJS when qualifying a Telegram-specific bug.

Example after building `libquickjs.a` in that checkout:

```sh
cc -O1 -g -I /path/to/telegram-quickjs \
  sbx.c /path/to/telegram-quickjs/libquickjs.a -lm -ldl -lpthread -o sbx
./sbx ../payloads/engine-probe.js
```

For memory-safety work, rebuild the engine and harness with matching
`-fsanitize=address,undefined -fno-omit-frame-pointer` flags. Record the fork
commit, compiler version, flags, and the full sanitizer report with each case.
