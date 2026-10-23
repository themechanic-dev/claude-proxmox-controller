"""A short sound when Claude's approval window opens (Claude Access → Play a sound; the user's wish, 23/10): plain
tones made here — no melodies, no sound files, no extra libraries — written once as WAV into the app's data folder and
played by the system: winsound on Windows, PipeWire / PulseAudio / ALSA's player on Linux, afplay on macOS."""

from __future__ import annotations

import io
import math
import shutil
import struct
import subprocess
import sys
import threading
import wave
from pathlib import Path

from . import procs, store

RATE = 44100
SOUNDS = (("double-beep", "Double beep"), ("beep", "Beep"), ("bell", "Bell"))
DEFAULT = "double-beep"
LINUX_PLAYERS = (("pw-play",), ("paplay",), ("aplay", "-q"), ("afplay",))  # the first found plays


def _tone(partials: list[tuple[float, float]], seconds: float, attack: float = 0.008, release: float = 0.03,
          decay: float | None = None) -> list[float]:
    """Sine partials (frequency, loudness) with a soft start and end — no clicks — and an optional fade."""
    out = []
    for i in range(int(RATE * seconds)):
        t = i / RATE
        env = min(1.0, t / attack) * min(1.0, (seconds - t) / release)
        if decay:
            env *= math.exp(-t / decay)
        out.append(env * sum(a * math.sin(2 * math.pi * f * t) for f, a in partials))
    return out


def samples(name: str) -> list[float]:
    """The sound, from −1 to 1. ValueError for a name not known."""
    if name == "beep":
        return _tone([(880, 1.0), (1760, 0.12)], 0.22)
    if name == "double-beep":
        pip = _tone([(1000, 1.0), (2000, 0.1)], 0.11)
        return pip + [0.0] * int(RATE * 0.09) + pip
    if name == "bell":
        return _tone([(660, 1.0), (1320, 0.45), (1822, 0.3), (3564, 0.12)], 1.6, attack=0.003, release=0.2,
                     decay=0.45)
    raise ValueError(f"Unknown sound '{name}'. Known: {', '.join(n for n, _ in SOUNDS)}.")


def wav_bytes(name: str) -> bytes:
    """The sound as a 16-bit mono WAV, its loudest point at half the scale: firm, not harsh."""
    data = samples(name)
    scale = 0.5 / (max(abs(s) for s in data) or 1)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(b"".join(struct.pack("<h", round(max(-1.0, min(1.0, s * scale)) * 32767)) for s in data))
    return buf.getvalue()


def path_of(name: str) -> Path:
    """The sound's WAV file in the app's data folder, written the first time."""
    path = store.data_dir() / "sounds" / f"{name}.wav"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(wav_bytes(name))
        tmp.replace(path)
    return path


def player(which=shutil.which) -> list[str] | None:
    """The command that plays a WAV file here (not Windows), or None."""
    for cmd in LINUX_PLAYERS:
        if which(cmd[0]):
            return list(cmd)
    return None


def play(name: str) -> bool:
    """Plays the sound without waiting for it. False where nothing can play it (no player found)."""
    path = path_of(name)
    if sys.platform.startswith("win"):
        import winsound
        winsound.PlaySound(str(path), winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)
        return True
    cmd = player()
    if cmd is None:
        return False
    proc = subprocess.Popen([*cmd, str(path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, **procs.hidden())
    threading.Thread(target=proc.wait, daemon=True).start()  # reaped when it ends
    return True


def chosen(settings: dict) -> str | None:
    """The sound to play when Claude asks, or None when it is off (Claude Access → Play a sound)."""
    claude = settings.get("claude", {})
    if not claude.get("sound_on"):
        return None
    name = claude.get("sound", DEFAULT)
    return name if name in dict(SOUNDS) else DEFAULT


NO_PLAYER = ("No program to play sounds was found: Proxmox Controller uses pw-play (PipeWire), paplay (PulseAudio) "
             "or aplay (ALSA).")
