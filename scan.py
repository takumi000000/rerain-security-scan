#!/usr/bin/env python3
"""ReRain セキュリティ点検（rerain-security-scan）: Mac/Windows・コード・GitHub・Web/Vercel・AWS・Gmail を読み取り専用で横断チェックする。

使い方:
  rerain-security-scan                    # 全部
  rerain-security-scan --only mac,web     # 一部だけ
  rerain-security-scan --skip repos       # 重いものを外す
  rerain-security-scan --notify --open    # 新しい高リスクがあれば通知、終わったらレポートを開く
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import tomllib
import traceback
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sscan import aws, azure, cloudflare, gcp, github, gmail, mac, report, repos, supabase, web, win  # noqa: E402
from sscan.common import BRAND, IS_WIN, ROOT, SLUG, WHOLE, Result, run  # noqa: E402

MODULES = {"mac": mac, "windows": win, "repos": repos, "github": github, "web": web, "aws": aws, "gcp": gcp, "azure": azure,
           "cloudflare": cloudflare, "supabase": supabase, "gmail": gmail}
REPORTS = Path(os.environ.get("SECURITY_SCAN_REPORTS", ROOT / "reports"))
# 旧名（security-scan）の設定も読む
CONFIG_CANDIDATES = [Path.home() / ".config" / SLUG / "config.toml", Path.home() / ".config/security-scan/config.toml", ROOT / "config.toml"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--skip", default="")
    ap.add_argument("--config", default="", help="既定は ~/.config/rerain-security-scan/config.toml → 同梱の config.toml。無くても自動検出で動く")
    ap.add_argument("--demo", action="store_true", help="見本データでレポートだけ作る（スクショ・動作確認用。何もスキャンしない）")
    ap.add_argument("--notify", action="store_true", help="新しい緊急/高があればmacOS通知")
    ap.add_argument("--open", action="store_true", help="終了後にレポートをブラウザで開く")
    ap.add_argument("--log", default="", help="標準出力をこのファイルに追記する（タスクスケジューラ用）")
    a = ap.parse_args()
    if a.log:
        Path(a.log).parent.mkdir(parents=True, exist_ok=True)
        sys.stdout = sys.stderr = open(a.log, "a", encoding="utf-8", errors="replace")
        print(f"\n===== {datetime.now():%Y-%m-%d %H:%M:%S} =====", flush=True)
    elif IS_WIN:
        # リダイレクト時に cp932 で書けない文字（▶ 等）で落ちないようにする
        for s in (sys.stdout, sys.stderr):
            try:
                s.reconfigure(errors="replace")
            except AttributeError:
                pass

    cfg_path = Path(a.config) if a.config else next((p for p in CONFIG_CANDIDATES if p.exists()), None)
    cfg = tomllib.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path else {}
    mods = [m for m in (a.only.split(",") if a.only else MODULES) if m and m not in a.skip.split(",")]
    # 本体チェックは動いているOSのものだけ（--only で明示されたときはそのまま試して「確認できなかった」に出す）
    if sys.platform != "darwin" and "mac" in mods and not a.only:
        mods.remove("mac")
    if not IS_WIN and "windows" in mods and not a.only:
        mods.remove("windows")
    started = datetime.now()
    os.umask(0o077)  # レポートには弱点の一覧が入るので本人以外読めないようにする
    outdir = REPORTS / (started.strftime("%Y-%m-%d_%H%M%S") + ("_demo" if a.demo else ""))
    outdir.mkdir(parents=True, exist_ok=False)

    total = Result()
    if a.demo:
        from sscan import demo
        total = demo.result()
        mods = sorted({f.module for f in total.findings})
    for m in ([] if a.demo else mods):
        t = time.time()
        print(f"▶ {m} ...", flush=True)
        try:
            res = MODULES[m].scan(cfg)
        except Exception as e:  # noqa: BLE001  1モジュールの失敗で全体を止めない
            res = Result()
            # 例外文に秘密が混ざりうるので型名と発生箇所だけ残す
            tb = traceback.extract_tb(e.__traceback__)[-1]
            res.cov(m, "モジュール全体", "error", f"{type(e).__name__} at {Path(tb.filename).name}:{tb.lineno}", blocks=WHOLE)
            print(f"  ERROR {type(e).__name__} at {Path(tb.filename).name}:{tb.lineno}", flush=True)
        total.extend(res)
        print(f"  {len(res.findings)}件 / {time.time() - t:.0f}秒", flush=True)

    findings = [f.to_dict() for f in total.findings]
    coverage = [c.to_dict() for c in total.coverage]
    prev, prev_cov = (demo.previous(), []) if a.demo else _previous(outdir, set(mods))
    # 確認できなかった範囲は「解消」「新規」と判定しない（見えなかっただけの可能性がある）
    new, resolved = report.diff(findings, prev, coverage, prev_cov)
    meta = {"demo": a.demo, "started": started.strftime("%Y-%m-%d %H:%M"), "elapsed": int((datetime.now() - started).total_seconds()), "modules": mods}
    report.write(outdir, meta, findings, coverage, new, resolved)

    if not a.demo:  # 見本は latest を上書きしない（次回の差分が壊れるため）
        _update_latest(outdir)

    hot = [f for f in findings if f["key"] in new and f["severity"] in ("critical", "high")]
    print((outdir / "summary.md").read_text(encoding="utf-8"))
    print(f"レポート: {outdir / 'report.html'}")
    if a.notify and hot:
        msg = f"新しい緊急/高リスク {len(hot)}件: " + hot[0]["title"][:40]
        _notify(msg)
    if a.open:
        page = outdir / "report.html"
        if IS_WIN:
            try:
                os.startfile(str(page))  # noqa: S606  既定のブラウザで開く
            except OSError:
                print(f"ブラウザで開けませんでした: {page}")
        else:
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            rc, _, err = run([opener, str(page)])
            if rc != 0:
                print(f"ブラウザで開けませんでした（{opener}）: {page}")


def _update_latest(outdir: Path):
    """reports/latest を最新に向ける。Windows はシンボリックリンクに管理者権限が要るので、中身のコピーで代える。"""
    latest = REPORTS / "latest"
    if latest.is_symlink() or latest.is_file():
        latest.unlink()
    elif latest.is_dir():
        shutil.rmtree(latest)
    try:
        latest.symlink_to(outdir.name, target_is_directory=True)
    except OSError:
        shutil.copytree(outdir, latest)


def _notify(msg: str):
    if sys.platform == "darwin":
        # 文言はスクリプトに埋め込まず argv で渡す（finding由来の文字列をAppleScriptとして解釈させない）
        run(["osascript", "-e", "on run argv", "-e", 'display notification (item 1 of argv) with title (item 2 of argv) sound name "Basso"',
             "-e", "end run", msg, BRAND])
    elif IS_WIN:
        # 文言は環境変数で渡す（finding由来の文字列をPowerShellとして解釈させない）
        ps = ("Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
              "$n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; $n.Visible = $true; "
              "$n.ShowBalloonTip(10000, $env:SSCAN_TITLE, $env:SSCAN_MSG, 'Warning'); Start-Sleep -Seconds 10; $n.Dispose()")
        os.environ["SSCAN_MSG"] = msg
        os.environ["SSCAN_TITLE"] = BRAND
        run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], 30)


def _previous(current: Path, mods: set[str]):
    """同じモジュール構成で回した直近のレポートを前回とみなす（部分実行で差分が壊れないように）。"""
    for d in sorted(REPORTS.glob("20*"), reverse=True):
        if d == current or d.name.endswith("_demo") or not (d / "findings.json").exists():
            continue
        try:
            data = json.loads((d / "findings.json").read_text(encoding="utf-8"))
            if set(data["meta"]["modules"]) >= mods:
                return ([f for f in data["findings"] if f["module"] in mods and {"key", "severity", "title", "target"} <= f.keys()],
                        data.get("coverage", []))
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return None, []


if __name__ == "__main__":
    main()
