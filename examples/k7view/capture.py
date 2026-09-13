#!/usr/bin/env python3
"""Screen-capture k7view into an mp4.

Runs on the workstation that can reach the k7view URL (use an SSH
tunnel to the gym node: `ssh -N -L 7475:127.0.0.1:7474 root@$K7_NODE_IP`).
Drives headless Chrome over CDP, polls PNG frames at a fixed rate, and
encodes with ffmpeg. Not part of the k7d node runtime — the UI itself
stays a static stdlib-served page.

Deps (capture box only): google-chrome, ffmpeg, `pip install websockets`.

Typical take:
  python3 capture.py --url http://127.0.0.1:7475/ --out /tmp/take1 \
      --fps 8 --start-phase agent --stop-phase idle --max-s 480
Then trim/speed with ffmpeg (see README "Recording the demo video").
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import websockets

CDP_PORT = 9223


def ensure_chrome(width: int, height: int) -> None:
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=1)
        return
    except OSError:
        pass
    chrome = (
        shutil.which("google-chrome")
        or shutil.which("chromium")
        or shutil.which("chromium-browser")
    )
    if not chrome:
        raise SystemExit("no chrome/chromium on PATH")
    subprocess.Popen(
        [
            chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
            f"--remote-debugging-port={CDP_PORT}",
            "--user-data-dir=/tmp/k7view-capture-profile",
            f"--window-size={width},{height}", "--hide-scrollbars", "about:blank",
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=1
            )
            return
        except OSError:
            time.sleep(0.2)
    raise SystemExit("chrome did not come up")


def run_phase(view_url: str) -> str:
    try:
        with urllib.request.urlopen(f"{view_url}/api/state", timeout=2) as r:
            return json.load(r).get("run", {}).get("phase", "")
    except OSError:
        return ""


async def capture(ns: argparse.Namespace) -> None:
    out = Path(ns.out)
    frames = out / "frames"
    frames.mkdir(parents=True, exist_ok=True)
    ensure_chrome(ns.width, ns.height)
    tabs = json.loads(
        urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json").read()
    )
    page = next(t for t in tabs if t["type"] == "page")
    view = ns.url.rstrip("/")
    async with websockets.connect(
        page["webSocketDebuggerUrl"], max_size=64 * 1024 * 1024
    ) as ws:
        mid = 0

        async def cmd(method: str, **params):
            nonlocal mid
            mid += 1
            await ws.send(json.dumps({"id": mid, "method": method, "params": params}))
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == mid:
                    if "error" in msg:
                        raise RuntimeError(msg["error"])
                    return msg.get("result", {})

        await cmd(
            "Emulation.setDeviceMetricsOverride",
            width=ns.width, height=ns.height, deviceScaleFactor=1, mobile=False,
        )
        await cmd("Page.navigate", url=ns.url)
        await asyncio.sleep(2)

        if ns.start_phase:
            print(f"waiting for run phase containing '{ns.start_phase}' …", flush=True)
            t0 = time.time()
            while ns.start_phase not in run_phase(view):
                if time.time() - t0 > ns.max_wait_s:
                    raise SystemExit(f"start phase never arrived in {ns.max_wait_s}s")
                await asyncio.sleep(1)

        print(f"recording at {ns.fps} fps → {frames}", flush=True)
        n = 0
        t0 = time.time()
        stop_seen_at: float | None = None
        while True:
            tick = t0 + n / ns.fps
            delay = tick - time.time()
            if delay > 0:
                await asyncio.sleep(delay)
            shot = await cmd("Page.captureScreenshot", format="png")
            (frames / f"f_{n:05d}.png").write_bytes(base64.b64decode(shot["data"]))
            n += 1
            elapsed = time.time() - t0
            if elapsed > ns.max_s:
                print(f"max duration {ns.max_s}s reached", flush=True)
                break
            if ns.stop_phase and run_phase(view) == ns.stop_phase:
                if stop_seen_at is None:
                    stop_seen_at = time.time()
                elif time.time() - stop_seen_at > ns.tail_s:
                    print(f"stop phase '{ns.stop_phase}' held {ns.tail_s}s", flush=True)
                    break
            else:
                stop_seen_at = None
        mp4 = out / "capture.mp4"
        subprocess.run(
            [
                "ffmpeg", "-y", "-framerate", str(ns.fps),
                "-i", str(frames / "f_%05d.png"),
                "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", str(mp4),
            ],
            check=True,
        )
        print(f"wrote {mp4} ({n} frames, {n / ns.fps:.0f}s)", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default="http://127.0.0.1:7475/")
    ap.add_argument("--out", required=True)
    ap.add_argument("--fps", type=int, default=8)
    ap.add_argument("--width", type=int, default=1920)
    ap.add_argument("--height", type=int, default=1080)
    ap.add_argument("--start-phase", default="", help="wait until run.phase contains this")
    ap.add_argument("--stop-phase", default="", help="stop once run.phase equals this")
    ap.add_argument("--tail-s", type=float, default=6.0, help="keep recording this long after stop phase")
    ap.add_argument("--max-s", type=float, default=600)
    ap.add_argument("--max-wait-s", type=float, default=900)
    asyncio.run(capture(ap.parse_args()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
