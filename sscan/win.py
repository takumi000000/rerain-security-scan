"""このWindows本体の設定チェック（管理者権限不要の範囲）。

実際の読み取りは同じフォルダの win_collect.ps1 が行い、ここでは結果のJSONを判定するだけ。
読み取り専用。設定の変更はしない。常駐・タスクの起動引数は秘密が入りうるので記録しない。
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from .common import WHOLE, Result, run_json, short_err, tool

M = "windows"
HOME = Path.home()
COLLECT = Path(__file__).resolve().parent / "win_collect.ps1"
PC = "このPC"

# Windows 11 の各バージョンのサポート終了日（Microsoft のライフサイクル公開情報。Home/Pro と Enterprise/Education）
WIN11 = {
    22000: ("21H2", date(2023, 10, 10), date(2024, 10, 8)),
    22621: ("22H2", date(2024, 10, 8), date(2025, 10, 14)),
    22631: ("23H2", date(2025, 11, 11), date(2026, 11, 10)),
    26100: ("24H2", date(2026, 10, 13), date(2027, 10, 12)),
    26200: ("25H2", date(2027, 10, 12), date(2028, 10, 10)),
}
WIN10_END = date(2025, 10, 14)


def scan(cfg: dict) -> Result:
    r = Result()
    ps = tool("powershell") or tool("pwsh")
    if not ps:
        r.cov(M, "Windows本体", "skip", "PowerShell が見つからない", blocks=WHOLE)
        return r
    data, err = run_json([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(COLLECT)], 300)
    if not isinstance(data, dict):
        r.cov(M, "Windows本体", "error", err or "PowerShell の結果を読めない", blocks=WHOLE)
        return r
    analyze(r, data, cfg.get("windows", {}), today=date.today())
    _files(r)
    return r


def _sec(r: Result, data: dict, name: str, label: str, blocks: list | None = None):
    """セクションを取り出す。取得に失敗していたら coverage に記録して None。"""
    v = data.get(name)
    if isinstance(v, dict) and "__error" in v:
        r.cov(M, label, "error", short_err(str(v["__error"])), blocks=blocks or [(label, "")])
        return None
    if v is None:
        r.cov(M, label, "error", "取得できなかった", blocks=blocks or [(label, "")])
    return v


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def analyze(r: Result, d: dict, cfg: dict, today: date):
    _os(r, d, today)
    _bitlocker(r, d)
    _antivirus(r, d)
    _firewall(r, d)
    _uac(r, d)
    _autologin(r, d)
    _screenlock(r, d)
    _updates(r, d, today)
    _listening(r, d, cfg)
    _rdp_smb(r, d)
    _accounts(r, d)
    _hardening(r, d)
    _sshd(r, d)
    _startup(r, d)
    _services(r, d)


# ---------------- OS ----------------

def _os(r: Result, d: dict, today: date):
    o = _sec(r, d, "os", "Windowsのバージョン", [("サポート", "")])
    if not o:
        return
    build = int(o.get("build") or 0)
    edition = str(o.get("edition") or "")
    ent = bool(re.search(r"Enterprise|Education", edition, re.I))
    ver = f"build {build}.{o.get('ubr') or 0} / {edition}"
    if 10240 <= build < 22000:
        if today > WIN10_END:
            r.add(M, "high", "Windows 10 のサポートが終了している", PC, f"{ver}（サポート終了 {WIN10_END}）",
                  "Windows 11 へアップグレードする。ハードが非対応なら、拡張セキュリティ更新（ESU）に登録して買い替えを計画する",
                  key="win|os-eos")
        else:
            r.cov(M, "Windowsのバージョン", "ok", ver)
        return
    if build in WIN11:
        name, home_end, ent_end = WIN11[build]
        end = ent_end if ent else home_end
        if today > end:
            r.add(M, "high", f"Windows 11 {name} のサポートが終了している", PC, f"{ver}（サポート終了 {end}）",
                  "設定 → Windows Update で最新バージョン（機能更新プログラム）に更新する。終了後はセキュリティ更新が来ない",
                  key="win|os-eos")
        elif (end - today).days <= 60:
            r.add(M, "medium", f"Windows 11 {name} のサポート終了が近い", PC, f"{ver}（サポート終了 {end}）",
                  "設定 → Windows Update で最新バージョン（機能更新プログラム）に更新する", key="win|os-eos")
        else:
            r.cov(M, "Windowsのバージョン", "ok", f"Windows 11 {name}（{ver}）")
    elif build > 26200:
        r.cov(M, "Windowsのバージョン", "ok", ver)
    else:
        r.cov(M, "Windowsのバージョン", "error", f"サポート期限の表に無いビルド: {ver}", blocks=[("サポート", "")])


# ---------------- ディスク暗号化 ----------------

def _bitlocker(r: Result, d: dict):
    b = _sec(r, d, "bitlocker", "ディスク暗号化", [("暗号化", "")])
    if not b:
        return
    v = b.get("protection")
    drive = b.get("drive") or "C:"
    if v in (1, 3, 6):
        r.cov(M, "ディスク暗号化", "ok", f"{drive} BitLocker/デバイスの暗号化 オン")
    elif v == 2:
        r.add(M, "critical", f"ディスク暗号化（BitLocker）がオフ: {drive}", PC, "BitLocker 状態 = オフ",
              "設定 → プライバシーとセキュリティ → デバイスの暗号化（Homeの場合）/ コントロールパネル → BitLocker（Proの場合）をオンにする。"
              "回復キーは必ずMicrosoftアカウント等に保存する。盗難・紛失時に全データが読まれるのを防ぐ", key="win|bitlocker")
    elif v == 5:
        r.add(M, "high", f"ディスク暗号化（BitLocker）が一時停止中: {drive}", PC, "BitLocker 状態 = 保護の一時停止",
              "コントロールパネル → BitLocker → 保護の再開。更新作業の後に戻し忘れていることが多い", key="win|bitlocker")
    elif v == 8:
        r.add(M, "high", f"ディスク暗号化が有効化待ち: {drive}", PC, "暗号化はされているが鍵が保護されていない（実質オフ）",
              "Microsoftアカウントでサインインするか、BitLocker 管理画面で保護を有効にする", key="win|bitlocker")
    elif v == 4:
        r.add(M, "high", f"ディスク暗号化を解除中: {drive}", PC, "BitLocker 状態 = 復号中", "意図した操作でなければ BitLocker を再度オンにする",
              key="win|bitlocker")
    else:
        r.cov(M, "ディスク暗号化", "error", f"状態を判定できない（値: {v}）。Home版で暗号化に非対応の機種の可能性", blocks=[("暗号化", "")])


# ---------------- ウイルス対策 ----------------

AV_BLOCKS = [("ウイルス対策", ""), ("リアルタイム", ""), ("ウイルス定義", ""), ("改ざん防止", "")]


def _antivirus(r: Result, d: dict):
    products = d.get("av_products")
    third = []
    if isinstance(products, list):
        for p in products:
            st = int(p.get("state") or 0)
            enabled = bool(st & 0x1000)
            outdated = bool(st & 0x10)
            nm = str(p.get("name") or "?")
            if "defender" not in nm.lower():
                third.append((nm, enabled, outdated))
    third_on = [t for t in third if t[1]]
    for nm, enabled, outdated in third:
        if enabled and outdated:
            r.add(M, "high", f"ウイルス対策ソフトの定義ファイルが古い: {nm}", PC, "", "ソフトを開いて更新する。期限切れの有料版なら更新するか Defender に戻す",
                  key=f"win|av-old|{nm}")

    df = d.get("defender")
    if isinstance(df, dict) and "__error" in df:
        if third_on:
            r.cov(M, "ウイルス対策", "ok", "他社製: " + ", ".join(t[0] for t in third_on))
        else:
            r.cov(M, "ウイルス対策", "error", short_err(df["__error"]), blocks=AV_BLOCKS)
        return
    if not isinstance(df, dict):
        r.cov(M, "ウイルス対策", "error", "取得できなかった", blocks=AV_BLOCKS)
        return
    if third_on and not df.get("realtime"):
        # 他社製が有効なら Defender は受動モードになるのが正常
        r.cov(M, "ウイルス対策", "ok", "他社製: " + ", ".join(t[0] for t in third_on))
        return
    if not df.get("av_enabled") or not df.get("realtime"):
        r.add(M, "critical", "ウイルス対策のリアルタイム保護がオフ", PC,
              f"Defender: 有効={df.get('av_enabled')} / リアルタイム保護={df.get('realtime')}",
              "Windows セキュリティ → ウイルスと脅威の防止 → 設定の管理 → リアルタイム保護 をオン。自分で切った覚えがなければ感染を疑う",
              key="win|defender-rtp")
    else:
        r.cov(M, "ウイルス対策", "ok", "Microsoft Defender リアルタイム保護 オン")
    age = int(df.get("signature_age") or 0)
    if age >= 7:
        r.add(M, "high" if age >= 14 else "medium", "ウイルス定義ファイルが古い", PC, f"{age}日前のまま",
              "Windows セキュリティ → ウイルスと脅威の防止 → 保護の更新 → 更新プログラムのチェック", key="win|defender-sig")
    if df.get("realtime") and not df.get("tamper"):
        r.add(M, "medium", "改ざん防止（Tamper Protection）がオフ", PC, "マルウェアがDefenderを無効化できる状態",
              "Windows セキュリティ → ウイルスと脅威の防止 → 設定の管理 → 改ざん防止 をオン", key="win|tamper")


# ---------------- ファイアウォール ----------------

def _firewall(r: Result, d: dict):
    fw = _sec(r, d, "firewall", "ファイアウォール", [("ファイアウォール", "")])
    if fw is None:
        return
    off = [p.get("name") for p in _as_list(fw) if str(p.get("enabled")).lower() != "true"]
    if off:
        sev = "high" if any(str(n).lower() in ("public", "パブリック") for n in off) else "medium"
        r.add(M, sev, "ファイアウォールがオフのネットワークがある", PC, "オフ: " + ", ".join(map(str, off)),
              "Windows セキュリティ → ファイアウォールとネットワーク保護 で全部（ドメイン/プライベート/パブリック）をオン",
              key="win|firewall")
    else:
        r.cov(M, "ファイアウォール", "ok")
    nets = d.get("network_category")
    if isinstance(nets, list):
        priv = [n.get("name") for n in nets if str(n.get("category")).lower() == "private"]
        if priv:
            r.add(M, "info", "「プライベート」扱いの接続中ネットワーク", PC, ", ".join(map(str, priv)),
                  "カフェ・ホテル・出先のWi-Fiなら「パブリック」に変更（設定 → ネットワーク → プロパティ）。プライベートだと共有機能が見える",
                  key="win|private-net")


# ---------------- UAC・自動ログイン・画面ロック ----------------

def _uac(r: Result, d: dict):
    u = _sec(r, d, "uac", "ユーザーアカウント制御", [("UAC", "")])
    if not u:
        return
    if u.get("lua") is None:
        r.cov(M, "ユーザーアカウント制御", "error", "設定値を読めない", blocks=[("UAC", "")])
    elif u.get("lua") == 0:
        r.add(M, "high", "UAC（ユーザーアカウント制御）が無効", PC, "EnableLUA = 0",
              "コントロールパネル → ユーザーアカウント → ユーザーアカウント制御設定の変更 で既定（上から2番目）に戻して再起動", key="win|uac")
    elif u.get("consent_admin") == 0:
        r.add(M, "medium", "UAC の確認が出ない設定（管理者操作が無言で通る）", PC, "ConsentPromptBehaviorAdmin = 0",
              "ユーザーアカウント制御設定の変更 で「通知しない」以外にする", key="win|uac")
    else:
        r.cov(M, "ユーザーアカウント制御", "ok")


def _autologin(r: Result, d: dict):
    a = _sec(r, d, "autologin", "自動ログイン", [("自動ログイン", "")])
    if not a:
        return
    if str(a.get("auto")) == "1":
        detail = f"ユーザー: {a.get('user') or '?'}"
        if a.get("has_password"):
            detail += "\nパスワードがレジストリに平文で保存されている（値は表示しない）"
        r.add(M, "high", "自動ログインが有効", PC, detail,
              "netplwiz で「ユーザーがこのコンピューターを使うには、ユーザー名とパスワードの入力が必要」にチェック。"
              "盗難・紛失時にそのまま中身を見られる", key="win|autologin")
    else:
        r.cov(M, "自動ログイン", "ok")


def _screenlock(r: Result, d: dict):
    s = _sec(r, d, "screenlock", "画面ロック", [("画面ロック", "")])
    if not s:
        return

    def _int(x, default=0):
        try:
            return int(str(x).strip())
        except (TypeError, ValueError):
            return default

    ss = str(s.get("ss_active")) == "1" and str(s.get("ss_secure")) == "1" and 0 < _int(s.get("ss_timeout")) <= 1800
    policy = 0 < _int(s.get("inactivity")) <= 1800
    lock = _as_list(s.get("console_lock"))
    sleep = _as_list(s.get("sleep_idle"))
    # スリープ復帰時のサインイン（既定オン）＋ AC 電源で30分以内にスリープ
    sleep_lock = bool(lock) and lock[0] == 1 and bool(sleep) and 0 < sleep[0] <= 1800
    if not lock and not sleep and not any(str(s.get(k) or "") for k in ("ss_active", "ss_secure", "ss_timeout")):
        r.cov(M, "画面ロック", "error", "設定値を読めない", blocks=[("画面ロック", "")])
        return
    if ss or policy or sleep_lock:
        how = "スクリーンセーバー" if ss else ("ポリシー" if policy else f"スリープ（{sleep[0] // 60}分）")
        r.cov(M, "画面ロック", "ok", f"放置時に自動ロック: {how}")
        return
    detail = [f"スクリーンセーバー: 有効={s.get('ss_active')} 再開時ロック={s.get('ss_secure')} 待ち={s.get('ss_timeout')}秒"]
    if lock:
        detail.append(f"スリープ復帰時のサインイン: {'要' if lock[0] == 1 else '不要'}")
    if sleep:
        detail.append("スリープまで(AC): " + ("しない" if sleep[0] == 0 else f"{sleep[0] // 60}分"))
    r.add(M, "medium", "席を離れても自動で画面ロックされない設定", PC, "\n".join(detail),
          "設定 → アカウント → サインイン オプション →「一定時間不在にした場合のサインイン」を有効に、かつ 設定 → 個人用設定 → ロック画面 → "
          "スクリーンセーバー で「再開時にログオン画面に戻る」＋10分以内。離席時は Windows+L を習慣に",
          key="win|screenlock")


# ---------------- 更新 ----------------

def _updates(r: Result, d: dict, today: date):
    u = _sec(r, d, "updates", "Windows Update", [("更新", "")])
    if not u:
        return
    last = u.get("last_hotfix")
    if not last:
        r.cov(M, "Windows Update", "error", "更新履歴を読めない", blocks=[("更新", "")])
    else:
        try:
            days = (today - date.fromisoformat(str(last)[:10])).days
        except ValueError:
            days = -1
        if days > 70:
            r.add(M, "high", "Windows Update が2か月以上適用されていない", PC, f"最後の更新: {last}（{u.get('last_hotfix_id')}・{days}日前）",
                  "設定 → Windows Update → 更新プログラムのチェック。止まっているなら「詳細オプション」で一時停止を解除", key="win|updates")
        elif days > 40:
            r.add(M, "medium", "直近の月例セキュリティ更新が未適用の可能性", PC, f"最後の更新: {last}（{u.get('last_hotfix_id')}・{days}日前）",
                  "設定 → Windows Update → 更新プログラムのチェック", key="win|updates")
        else:
            r.cov(M, "Windows Update", "ok", f"最後の更新 {last}")
    if u.get("reboot_pending"):
        r.add(M, "low", "再起動待ちの更新がある", PC, "再起動するまで修正が効かない", "作業の区切りで再起動する", key="win|reboot")


# ---------------- ポート ----------------

# Windows が既定で開けているもの（ファイアウォールで守られる前提）は指摘にしない。一覧には説明つきで出す
DEFAULT_LISTEN = {135, 5040, 7680, 5357}
SYSTEM_DYNAMIC = {"lsass", "wininit", "services", "svchost", "spoolsv"}
RISKY = {22: "SSH", 3389: "リモートデスクトップ", 5985: "WinRM", 5986: "WinRM", 445: "ファイル共有(SMB)", 139: "ファイル共有(NetBIOS)",
         5900: "VNC", 5939: "TeamViewer", 7070: "AnyDesk", 1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}
# よく見るポートの「これは何か」。プロセス名と合わせて素人でも判断できるようにする
KNOWN = {
    135: "Windowsの部品同士の呼び出し口（RPC）。Windows標準",
    139: "古い方式のファイル共有（NetBIOS）",
    445: "ファイル共有（SMB）。共有フォルダ・プリンター共有で使う",
    5040: "近くの端末との連携（接続デバイス プラットフォーム）。Windows標準",
    7680: "Windows Update の配信の最適化（他のPCと更新を分け合う）。Windows標準",
    5357: "ネットワーク上の機器の自動発見（WSD）。Windows標準",
    22: "SSHサーバー（遠隔ログイン）",
    3389: "リモートデスクトップ",
    5985: "WinRM（PowerShellの遠隔操作）", 5986: "WinRM（PowerShellの遠隔操作・暗号化）",
    5900: "VNC（画面共有）",
    5939: "TeamViewer（遠隔操作ソフト）。サポート詐欺で悪用されやすい", 7070: "AnyDesk（遠隔操作ソフト）。サポート詐欺で悪用されやすい",
    80: "Webサーバー", 443: "Webサーバー（HTTPS）", 8080: "Webサーバー（開発・代理）",
    3000: "開発用Webサーバー（Node.js 等）", 5173: "開発用Webサーバー（Vite）", 8000: "開発用Webサーバー（Python 等）", 8888: "Jupyter 等",
    1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
    5353: "mDNS（機器の名前解決）", 1900: "UPnP（機器の自動発見）", 2869: "UPnP（機器の自動発見）",
    9100: "プリンター", 631: "プリンター（IPP）",
}


def _port_label(port: int, proc: str) -> str:
    if port in KNOWN:
        return KNOWN[port]
    if port >= 49152 and proc.lower() in SYSTEM_DYNAMIC:
        return "Windowsの部品が使う一時的な番号（RPC動的ポート）。Windows標準"
    return ""


def _what(it: dict) -> str:
    """プロセスの説明を1行にする（名前・説明・発行元・署名・中で動くサービス）。"""
    proc = str(it.get("proc") or "?")
    bits = [f"{proc}（PID {it.get('pid')}）" if it.get("pid") is not None else proc]
    desc, comp = str(it.get("description") or ""), str(it.get("company") or "")
    if desc and desc.lower() != proc.lower():
        bits.append(desc)
    sig = str(it.get("signature") or "")
    if comp or it.get("signer"):
        bits.append("発行元: " + (comp or str(it.get("signer"))))
    if sig and sig.lower() != "valid":
        bits.append(f"署名: {sig}")
    line = " / ".join(bits)
    svcs = [str(x) for x in _as_list(it.get("services")) if x]
    if svcs:
        line += "\n    サービス: " + ", ".join(svcs[:6]) + (f" ほか{len(svcs) - 6}件" if len(svcs) > 6 else "")
    if it.get("path"):
        line += f"\n    場所: {it.get('path')}"
    return line


def _listening(r: Result, d: dict, cfg: dict):
    items = _sec(r, d, "listening", "待ち受けポート", [("ポート", "")])
    if items is None:
        return
    ignore = set(cfg.get("ignore_ports", []))
    by_port: dict[int, dict] = {}
    for it in _as_list(items):
        port = int(it.get("port") or 0)
        g = by_port.setdefault(port, {"exposed": False, "addrs": set(), "procs": {}})
        g["exposed"] |= not it.get("local")
        g["addrs"].add(str(it.get("addr") or ""))
        g["procs"].setdefault(str(it.get("pid")), it)

    inventory = []
    for port in sorted(by_port):
        g = by_port[port]
        procs = list(g["procs"].values())
        names = {str(p.get("proc") or "").lower() for p in procs}
        label = _port_label(port, next(iter(names), ""))
        scope = "外から接続可" if g["exposed"] else "このPC内だけ"
        whats = "\n  ".join(_what(p) for p in procs)
        inventory.append(f"tcp/{port}  [{scope}]  {label or '（用途は下のプロセスで判断）'}\n  {whats}")

        if not g["exposed"] or port in ignore:
            continue
        default = port in DEFAULT_LISTEN or (port >= 49152 and names <= SYSTEM_DYNAMIC)
        if default:
            continue
        unsigned_user = any(re.match(r"(?i)^[a-z]:\\Users\\", str(p.get("path") or "")) and str(p.get("signature") or "").lower() != "valid"
                            for p in procs)
        name = RISKY.get(port)
        if port in (139, 445) and names <= {"system"}:
            sev, note = "info", "共有フォルダ用。パブリックネットワークではファイアウォールが塞ぐ"
        elif unsigned_user:
            sev, note = "medium", "ユーザーフォルダにある署名のないプログラムが外からの接続を待っている"
        elif name:
            sev, note = "medium", ""
        else:
            sev, note = "low", ""
        detail = (f"{label}\n" if label else "") + (note + "\n" if note else "") + \
            "待ち受け: " + ", ".join(sorted(a for a in g["addrs"] if a)) + "\n" + "\n".join(_what(p) for p in procs)
        r.add(M, sev, f"外部から接続を受け付けるポート {port}" + (f"（{name}）" if name else ""), f"tcp/{port}", detail,
              "心当たりがなければ、上の「場所」のソフトを確認。使っていない共有機能・開発サーバーなら止めるか 127.0.0.1 にバインドする。"
              "公衆Wi-Fiでは接続を「パブリック」に",
              key=f"win|port|{port}")

    if inventory:
        n_ext = sum(1 for g in by_port.values() if g["exposed"])
        r.add(M, "info", f"待ち受けポートの一覧（外から接続可 {n_ext}件・このPC内だけ {len(by_port) - n_ext}件）", PC,
              "\n".join(inventory), "", key="win|port-inventory")


# ---------------- RDP・SMBv1 ----------------

def _rdp_smb(r: Result, d: dict):
    rdp = _sec(r, d, "rdp", "リモートデスクトップ", [("リモートデスクトップ", "")])
    if rdp and rdp.get("deny") is None:
        r.cov(M, "リモートデスクトップ", "error", "設定値を読めない", blocks=[("リモートデスクトップ", "")])
    elif rdp:
        if rdp.get("deny") == 0:
            if rdp.get("nla") == 0:
                r.add(M, "high", "リモートデスクトップが有効で、ネットワークレベル認証(NLA)がオフ", PC, "fDenyTSConnections=0 / UserAuthentication=0",
                      "使わないなら 設定 → システム → リモートデスクトップ をオフ。使うならNLAを必須にする", key="win|rdp")
            else:
                r.add(M, "medium", "リモートデスクトップが有効", PC, "外から入られる入口になる",
                      "使っていなければ 設定 → システム → リモートデスクトップ をオフ", key="win|rdp")
        else:
            r.cov(M, "リモートデスクトップ", "ok", "無効")
    smb = _sec(r, d, "smb1", "SMBv1", [("SMBv1", "")])
    if smb:
        on = []
        if smb.get("client_start") not in (None, 4):
            on.append("クライアント")
        if smb.get("server_start") not in (None, 4) and smb.get("server_param") != 0:
            on.append("サーバー")
        if on:
            r.add(M, "high", "古いファイル共有（SMBv1）が有効", PC, "有効: " + "・".join(on) + "（WannaCry 等が使った方式）",
                  "コントロールパネル → Windowsの機能の有効化または無効化 →「SMB 1.0/CIFS ファイル共有のサポート」のチェックを外す。"
                  "古いNAS・複合機が使っていないか先に確認", key="win|smb1")
        else:
            r.cov(M, "SMBv1", "ok", "無効")


# ---------------- アカウント・その他の防御 ----------------

def _accounts(r: Result, d: dict):
    a = _sec(r, d, "accounts", "ローカルアカウント", [("Guest", ""), ("Administrator", "")])
    if not a:
        return
    if a.get("guest_enabled"):
        r.add(M, "high", "Guest アカウントが有効", PC, "", "コンピューターの管理 → ローカルユーザーとグループ で無効化（管理者で実行）", key="win|guest")
    if a.get("builtin_admin_enabled"):
        r.add(M, "medium", "組み込みの Administrator アカウントが有効", PC, "名前が知られているため総当たりの標的になる",
              "普段は使わないなら無効化（管理者で net user Administrator /active:no）", key="win|admin")
    if not a.get("guest_enabled") and not a.get("builtin_admin_enabled"):
        r.cov(M, "ローカルアカウント", "ok")


def _hardening(r: Result, d: dict):
    h = _sec(r, d, "hardening", "その他の防御機能", [("SmartScreen", ""), ("メモリ整合性", ""), ("セキュアブート", "")])
    if not h:
        return
    if str(h.get("smartscreen")).lower() == "off" or h.get("smartscreen_policy") == 0:
        r.add(M, "medium", "SmartScreen（危険なアプリ・ダウンロードの警告）がオフ", PC, "",
              "Windows セキュリティ → アプリとブラウザーの制御 → 評価ベースの保護 をオン", key="win|smartscreen")
    if h.get("hvci") in (None, 0):
        r.add(M, "low", "メモリ整合性（コア分離）がオフ", PC, "悪意あるドライバーの読み込みを防ぐ機能",
              "Windows セキュリティ → デバイス セキュリティ → コア分離 → メモリ整合性 をオン（古いドライバーが非対応だと出せない）",
              key="win|hvci")
    if h.get("secure_boot") == 0:
        r.add(M, "medium", "セキュアブートがオフ", PC, "起動前に動くマルウェア（ブートキット）を防げない",
              "UEFI(BIOS)設定でセキュアブートを有効にする。メーカーの手順に従う", key="win|secureboot")


def _sshd(r: Result, d: dict):
    s = d.get("sshd")
    if isinstance(s, dict) and s.get("installed") and str(s.get("status")).lower() == "running":
        r.add(M, "medium", "OpenSSH サーバーが動いている", PC, f"起動の種類: {s.get('start')}",
              "使っていなければ サービス → OpenSSH SSH Server を停止して「無効」に", key="win|sshd")


# ---------------- 常駐（スタートアップ・タスク・サービス） ----------------

SIG_OK = {"valid"}


def _startup(r: Result, d: dict):
    for sec, label in (("startup", "スタートアップ"), ("tasks", "タスクスケジューラ")):
        items = _sec(r, d, sec, label, [("常駐", "")])
        if items is None:
            continue
        for it in _as_list(items):
            name, where, exe = str(it.get("name") or "?"), str(it.get("where") or ""), str(it.get("exe") or "")
            sig = str(it.get("signature") or "")
            in_user = bool(re.match(r"(?i)^[a-z]:\\Users\\", exe))
            sev, note = "info", ""
            if it.get("suspicious_dir"):
                sev, note = "high", "一時フォルダ・Downloads・Public から起動している。マルウェアの典型パターン"
            elif it.get("lolbin"):
                sev, note = "medium", "スクリプト実行系（PowerShell・mshta・rundll32 等）から起動している。正規ソフトにもあるが乗っ取りでよく使われる"
            elif exe and not it.get("exists"):
                sev, note = "low", "起動先のファイルが存在しない（残骸）"
            elif it.get("exists") and sig.lower() not in SIG_OK and in_user:
                sev, note = "medium", f"ユーザーフォルダにある、正式な署名のないプログラム（署名: {sig or '不明'}）"
            kind = {"run": "Run", "startup_folder": "スタートアップフォルダ", "task": "タスク"}.get(str(it.get("kind")), "")
            fix = ""
            if sev != "info":
                fix = ("心当たりがなければ タスクマネージャー → スタートアップ アプリ で無効化してから調べる" if sec == "startup"
                       else "心当たりがなければ タスクスケジューラで無効化してから調べる")
            r.add(M, sev, f"常駐プログラム: {name}", f"{kind} {where}".strip(),
                  (note + "\n" if note else "") + f"起動: {exe or '?'}（引数は秘密が入りうるので記録しない）", fix,
                  key=f"winstart|{sec}|{where}|{name}")
        r.cov(M, label, "ok", f"{len(_as_list(items))}件")


def _services(r: Result, d: dict):
    items = _sec(r, d, "services", "サービス", [("サービス", "")])
    if items is None:
        return
    for s in _as_list(items):
        name = str(s.get("name") or "?")
        if s.get("user_writable"):
            r.add(M, "high", f"サービスがユーザーの書き換えられる場所から起動: {name}", PC,
                  f"{s.get('display')}\n起動: {s.get('exe')}（実行アカウント: {s.get('account')}）\n"
                  "ファイルをすり替えられると管理者(SYSTEM)権限を取られる",
                  "心当たりがなければ サービス で停止して「無効」に。正規ソフトならベンダーに報告し、Program Files 配下に入れ直す",
                  key=f"winsvc|{name}")
        elif s.get("unquoted"):
            r.add(M, "medium", f"サービスの起動パスに引用符が無い: {name}", PC,
                  f"{s.get('display')}\n起動: {s.get('exe')}\n空白入りのパスで、途中のフォルダに置いたプログラムが代わりに起動されうる",
                  "ソフトを最新版に更新する。直らなければベンダーに報告（レジストリの ImagePath を引用符で囲む修正は管理者作業）",
                  key=f"winsvc|{name}")


# ---------------- ファイル（PowerShell不要の範囲） ----------------

def _files(r: Result):
    ak = HOME / ".ssh" / "authorized_keys"
    if ak.is_file() and ak.stat().st_size > 0:
        n = sum(1 for l in ak.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith("#"))
        r.add(M, "info", "このPCへSSHログインできる公開鍵が登録されている", str(ak), f"{n}件",
              "心当たりのない鍵があれば削除する（OpenSSHサーバーが止まっていれば影響なし）")
    cred = HOME / ".aws" / "credentials"
    if cred.is_file():
        r.add(M, "medium", "AWSの長期アクセスキーファイルが存在する", str(cred), "SSOを使っている環境では通常不要",
              "中身のキーが使われていないかIAMで確認し、不要なら無効化→ファイル削除。SSO(aws sso login)へ寄せる")
