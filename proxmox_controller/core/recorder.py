"""Recording a guest's console as a video: an MP4 with H.264, and the VM's sound as AAC when it has a SPICE sound card.

The picture comes from the console's VNC, which every guest has (a desktop, Ubuntu Server's text screen, a
container's terminal), asked for in Tight, with the pointer drawn in. The sound comes from SPICE
(core/spice_audio.py): QEMU gives a Proxmox VM's sound to SPICE only. Nothing shows on this computer's screen while a
recording runs; the app says that one does.

Frames are taken at a steady rate (the last picture again while nothing changes), the sound is kept in step with
the clock (silence where the guest played none), and both go to the system's own encoder: GStreamer (gst-launch-1.0
with openh264 or x264) on Linux, Media Foundation on Windows, which every Windows 10/11 has.

Measured before this was written (10/11/2026, PVE 9.2, a 1920×1080 Ubuntu desktop): a whole screen changing arrives
about 1.5 times a second (QEMU's limit: Proxmox starts VNC without its lossy mode, so no JPEG), a terminal printing
fast about 5 updates a second; openh264 encodes 1080p30 2.2 times faster than real time on one core, Media Foundation
3.6 times on four."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

from .rfb import RfbClient
from .tight import TightDecoder

AUDIO_RATE, AUDIO_CHANNELS = 48000, 2   # what QEMU's SPICE playback sends
CUSHION_S = 0.15        # sound held back this long, so that a late packet does not leave a gap
BACKLOG_S = 0.6         # more sound than this waiting: the oldest goes, to stay in step with the picture
DEFAULT_MAX_S = 3600
MAX_MAX_S = 4 * 3600
BIG_PIXELS = 2_200_000  # above about 1920×1080: 15 frames a second instead of 30
WINDOWS = sys.platform.startswith("win")
GST_HINT = ("Recording a console needs GStreamer: sudo apt install gstreamer1.0-tools gstreamer1.0-plugins-base "
            "gstreamer1.0-plugins-good gstreamer1.0-plugins-bad (the app's .deb package brings them).")


class RecordError(Exception):
    pass


def fps_for(w: int, h: int) -> int:
    return 30 if w * h <= BIG_PIXELS else 15


def bitrate_for(w: int, h: int, fps: int) -> int:
    return int(min(12_000_000, max(1_500_000, w * h * fps * 0.08)))


def videos_folder() -> Path:
    """The system's videos folder (Videos), in a folder of its own."""
    base = ""
    try:
        from PySide6.QtCore import QStandardPaths
        base = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.MoviesLocation)
    except Exception:
        pass
    return Path(base or Path.home() / "Videos") / "Proxmox Controller"


def system_env() -> dict:
    """The environment for a program of the system (gst-launch-1.0): a packaged app (PyInstaller) points
    LD_LIBRARY_PATH at its own libraries, which the system's programs must not load."""
    env = dict(os.environ)
    if getattr(sys, "frozen", False):
        original = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if original:
            env["LD_LIBRARY_PATH"] = original
        else:
            env.pop("LD_LIBRARY_PATH", None)
    return env


def file_for(name: str, vmid: int, folder: Path | None = None) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")[:40] or "guest"
    folder = folder or videos_folder()
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{vmid}-{safe}-{time.strftime('%Y-%m-%d_%H-%M-%S')}.mp4"


# -- encoders: frames are 32-bit, blue-green-red-unused, top row first; sound 16-bit stereo 48 kHz --------------------

class GstEncoder:
    """gst-launch-1.0: the frames on its standard input, the sound through a second pipe, into an MP4."""

    VIDEO = (("openh264enc", lambda bps, fps: [f"bitrate={bps}", f"gop-size={fps * 2}"]),
             ("x264enc", lambda bps, fps: ["speed-preset=veryfast", "tune=zerolatency", f"bitrate={bps // 1000}",
                                           f"key-int-max={fps * 2}"]))
    AUDIO = (("avenc_aac", ["bitrate=128000"]), ("voaacenc", ["bitrate=128000"]), ("fdkaacenc", ["bitrate=128000"]))
    NEEDED = ("fdsrc", "rawvideoparse", "videoconvert", "h264parse", "mp4mux", "filesink")
    NEEDED_AUDIO = ("rawaudioparse", "audioconvert", "aacparse")

    @staticmethod
    def has(element: str) -> bool:
        inspect = shutil.which("gst-inspect-1.0")
        if not inspect:
            return False
        try:
            return subprocess.run([inspect, "--exists", element], stdin=subprocess.DEVNULL, env=system_env(),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def __init__(self, path: Path, w: int, h: int, fps: int, audio: bool):
        launch = shutil.which("gst-launch-1.0")
        if not launch:
            raise RecordError(GST_HINT)
        missing = [e for e in self.NEEDED if not self.has(e)]
        video = next(((n, f) for n, f in self.VIDEO if self.has(n)), None)
        if missing or video is None:
            raise RecordError(f"GStreamer lacks {', '.join(missing or ['an H.264 encoder'])}. {GST_HINT}")
        sound = None
        self.note = ""
        if audio:
            sound = next(((n, a) for n, a in self.AUDIO if self.has(n)), None)
            if sound is None or not all(self.has(e) for e in self.NEEDED_AUDIO):
                sound, self.note = None, "GStreamer has no AAC encoder here: recorded without sound."
        self.audio_on = sound is not None
        queue = ["queue", "max-size-time=3000000000", "max-size-bytes=0", "max-size-buffers=0"]
        args = [launch, "-q", "-e",
                "fdsrc", "fd=0", f"blocksize={w * h * 4}", "!",
                "rawvideoparse", f"width={w}", f"height={h}", "format=bgrx", f"framerate={fps}/1", "!",
                "videoconvert", "!", "video/x-raw,format=I420", "!",
                video[0], *video[1](bitrate_for(w, h, fps), fps), "!", "h264parse", "!", *queue, "!", "mux."]
        self.audio_fd: int | None = None
        keep: tuple = ()
        if sound is not None:
            read_fd, self.audio_fd = os.pipe()
            try:
                import fcntl
                fcntl.fcntl(self.audio_fd, 1031, 1 << 20)  # F_SETPIPE_SZ: about 5 s of sound, so it never waits
            except (ImportError, OSError):
                pass
            keep = (read_fd,)
            args += ["fdsrc", f"fd={read_fd}", "!", "rawaudioparse", "format=pcm", "pcm-format=s16le",
                     f"sample-rate={AUDIO_RATE}", f"num-channels={AUDIO_CHANNELS}", "!", "audioconvert", "!",
                     sound[0], *sound[1], "!", "aacparse", "!", *queue, "!", "mux."]
        # (gst-launch escapes the spaces of each argument itself: a folder with spaces is fine)
        args += ["mp4mux", "name=mux", "faststart=true", "!", "filesink", f"location={path}"]
        self.path = path
        self.log = tempfile.TemporaryFile()
        try:
            self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=self.log,
                                         pass_fds=keep, env=system_env())
        finally:
            for fd in keep:
                os.close(fd)

    def _failed(self, what: str) -> RecordError:
        self.log.seek(0)
        tail = self.log.read()[-600:].decode("utf-8", "replace").strip()
        return RecordError(f"{what}{': ' + tail if tail else ''}")

    def video(self, frame: bytes) -> None:
        try:
            self.proc.stdin.write(frame)
        except (BrokenPipeError, OSError) as e:
            raise self._failed(f"The video encoder stopped ({e})") from e

    def audio(self, pcm: bytes) -> None:
        view = memoryview(pcm)
        while view:
            try:
                n = os.write(self.audio_fd, view)
            except OSError as e:
                raise self._failed(f"The sound encoder stopped ({e})") from e
            view = view[n:]

    def close(self) -> None:
        for close in (self.proc.stdin.close, lambda: self.audio_fd is not None and os.close(self.audio_fd)):
            try:
                close()
            except OSError:
                pass
        try:
            code = self.proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise self._failed("The video did not finish in time")
        if code != 0 or not self.path.exists() or self.path.stat().st_size == 0:
            raise self._failed(f"The video encoder ended with {code}")
        self.log.close()


class MfEncoder:
    """Windows' Media Foundation Sink Writer, through ctypes: H.264 (High) and AAC into an MP4. Every call from the
    one thread that made it (COM)."""

    GUIDS = {
        "MT_MAJOR_TYPE": "48eba18e-f8c9-4687-bf11-0a74c9f96a8f",
        "MT_SUBTYPE": "f7e34c9a-42e8-4714-b74b-cb29d72c35e5",
        "MT_AVG_BITRATE": "20332624-fb0d-4d9e-bd0d-cbf6786c102e",
        "MT_INTERLACE_MODE": "e2724bb8-e676-4806-b4b2-a8d6efb44ccd",
        "MT_FRAME_SIZE": "1652c33d-d6b2-4012-b834-72030849a37d",
        "MT_FRAME_RATE": "c459a2e8-3d2c-4e44-b132-fee5156c7bb0",
        "MT_PIXEL_ASPECT_RATIO": "c6376a1e-8d0a-4027-be45-6d9a0ad39bb6",
        "MT_DEFAULT_STRIDE": "644b4e48-1e02-4516-b0eb-c01ca9d49ac6",
        "MT_MPEG2_PROFILE": "ad76a80b-2d5c-4e0b-b375-64e520137036",
        "MT_AUDIO_NUM_CHANNELS": "37e48bf5-645e-4c5b-89de-ada9e29b696a",
        "MT_AUDIO_SAMPLES_PER_SECOND": "5faeeae7-0290-4c31-9e8a-c534f68d9dba",
        "MT_AUDIO_BITS_PER_SAMPLE": "f2deb57f-40fa-4764-aa33-ed4f2d1ff669",
        "MT_AUDIO_AVG_BYTES_PER_SECOND": "1aab75c8-cfef-451c-ab95-ac034b8e1731",
        "MT_AUDIO_BLOCK_ALIGNMENT": "322de230-9eeb-43bd-ab7a-ff412251541d",
        "READWRITE_ENABLE_HARDWARE_TRANSFORMS": "a634a91c-822b-41b9-a494-4de4643612b0",
        "SINK_WRITER_DISABLE_THROTTLING": "08b845d8-2b74-4afe-9d53-be16d2d5ae4f",
        "MediaType_Video": "73646976-0000-0010-8000-00aa00389b71",
        "MediaType_Audio": "73647561-0000-0010-8000-00aa00389b71",
        "VideoFormat_H264": "34363248-0000-0010-8000-00aa00389b71",
        "VideoFormat_RGB32": "00000016-0000-0010-8000-00aa00389b71",
        "AudioFormat_AAC": "00001610-0000-0010-8000-00aa00389b71",
        "AudioFormat_PCM": "00000001-0000-0010-8000-00aa00389b71",
    }
    H264_HIGH = 100
    # vtable slots: IUnknown 0–2; IMFAttributes SetUINT32 21, SetUINT64 22, SetGUID 24; IMFSinkWriter AddStream 3,
    # SetInputMediaType 4, BeginWriting 5, WriteSample 6, Finalize 11; IMFMediaBuffer Lock 3, Unlock 4,
    # SetCurrentLength 6; IMFSample SetSampleTime 36, SetSampleDuration 38, AddBuffer 42

    def __init__(self, path: Path, w: int, h: int, fps: int, audio: bool):
        import ctypes
        import uuid
        self.ct = ctypes
        self.note = ""
        self.audio_on = audio
        self.fps, self.frame_100ns = fps, 10_000_000 // fps
        self.n_video = self.n_audio = 0
        self.objects: list = []

        class GUID(ctypes.Structure):
            _fields_ = [("a", ctypes.c_uint32), ("b", ctypes.c_uint16), ("c", ctypes.c_uint16),
                        ("d", ctypes.c_ubyte * 8)]
        self.GUID = GUID
        self.g = {}
        for name, text in self.GUIDS.items():
            g = GUID()
            ctypes.memmove(ctypes.byref(g), uuid.UUID(text).bytes_le, 16)
            self.g[name] = g
        self.mfplat = ctypes.WinDLL("mfplat")
        mfrw = ctypes.WinDLL("mfreadwrite")
        ctypes.WinDLL("ole32").CoInitializeEx(None, 0)  # (already initialized here is fine)
        self._check(self.mfplat.MFStartup(0x00020070, 0), "MFStartup")
        try:
            self._open(mfrw, path, w, h, fps, audio)
        except Exception:
            for obj in reversed(self.objects):
                self._release(obj)
            self.mfplat.MFShutdown()
            raise

    def _open(self, mfrw, path: Path, w: int, h: int, fps: int, audio: bool) -> None:
        ctypes = self.ct
        attrs = self._new(self.mfplat.MFCreateAttributes, 2)
        self._set32(attrs, "READWRITE_ENABLE_HARDWARE_TRANSFORMS", 1)
        self._set32(attrs, "SINK_WRITER_DISABLE_THROTTLING", 1)
        writer = ctypes.c_void_p()
        self._check(mfrw.MFCreateSinkWriterFromURL(ctypes.c_wchar_p(str(path)), None, attrs, ctypes.byref(writer)),
                    "MFCreateSinkWriterFromURL")
        self.writer = writer
        self.objects.append(writer)
        bps = bitrate_for(w, h, fps)
        vout = self._video_type(w, h, fps, "VideoFormat_H264", bps)
        vin = self._video_type(w, h, fps, "VideoFormat_RGB32", 0)
        self.video_stream = self._add(vout, vin, "video (H.264: Windows N needs the Media Feature Pack)")
        if audio:
            aout = self._audio_type("AudioFormat_AAC", True)
            ain = self._audio_type("AudioFormat_PCM", False)
            self.audio_stream = self._add(aout, ain, "sound (AAC)")
        self._call(self.writer, 5, (), "BeginWriting")

    # -- COM by vtable --
    def _check(self, hr: int, what: str) -> None:
        if hr < 0:
            raise RecordError(f"Windows Media Foundation refused {what} (0x{hr & 0xFFFFFFFF:08X}).")

    def _call(self, obj, index: int, argtypes: tuple, what: str, *args) -> None:
        ct = self.ct
        vtbl = ct.cast(obj, ct.POINTER(ct.POINTER(ct.c_void_p))).contents
        self._check(ct.WINFUNCTYPE(ct.c_long, ct.c_void_p, *argtypes)(vtbl[index])(obj, *args), what)

    def _release(self, obj) -> None:
        ct = self.ct
        if obj:
            vtbl = ct.cast(obj, ct.POINTER(ct.POINTER(ct.c_void_p))).contents
            ct.WINFUNCTYPE(ct.c_ulong, ct.c_void_p)(vtbl[2])(obj)

    def _new(self, factory, *args):
        obj = self.ct.c_void_p()
        self._check(factory(self.ct.byref(obj), *args), factory.__name__)
        self.objects.append(obj)
        return obj

    def _set32(self, obj, key: str, value: int) -> None:
        ct = self.ct
        self._call(obj, 21, (ct.POINTER(self.GUID), ct.c_uint32), key, ct.byref(self.g[key]), value)

    def _set64(self, obj, key: str, value: int) -> None:
        ct = self.ct
        self._call(obj, 22, (ct.POINTER(self.GUID), ct.c_uint64), key, ct.byref(self.g[key]), value)

    def _setguid(self, obj, key: str, value: str) -> None:
        ct = self.ct
        self._call(obj, 24, (ct.POINTER(self.GUID), ct.POINTER(self.GUID)), key, ct.byref(self.g[key]),
                   ct.byref(self.g[value]))

    def _video_type(self, w: int, h: int, fps: int, subtype: str, bps: int):
        t = self._new(self.mfplat.MFCreateMediaType)
        self._setguid(t, "MT_MAJOR_TYPE", "MediaType_Video")
        self._setguid(t, "MT_SUBTYPE", subtype)
        self._set32(t, "MT_INTERLACE_MODE", 2)  # progressive
        self._set64(t, "MT_FRAME_SIZE", (w << 32) | h)
        self._set64(t, "MT_FRAME_RATE", (fps << 32) | 1)
        self._set64(t, "MT_PIXEL_ASPECT_RATIO", (1 << 32) | 1)
        if bps:
            self._set32(t, "MT_AVG_BITRATE", bps)
            self._set32(t, "MT_MPEG2_PROFILE", self.H264_HIGH)
        else:
            self._set32(t, "MT_DEFAULT_STRIDE", w * 4)  # positive: the top row first
        return t

    def _audio_type(self, subtype: str, out: bool):
        t = self._new(self.mfplat.MFCreateMediaType)
        self._setguid(t, "MT_MAJOR_TYPE", "MediaType_Audio")
        self._setguid(t, "MT_SUBTYPE", subtype)
        self._set32(t, "MT_AUDIO_BITS_PER_SAMPLE", 16)
        self._set32(t, "MT_AUDIO_SAMPLES_PER_SECOND", AUDIO_RATE)
        self._set32(t, "MT_AUDIO_NUM_CHANNELS", AUDIO_CHANNELS)
        if out:
            self._set32(t, "MT_AUDIO_AVG_BYTES_PER_SECOND", 16000)  # 128 kbit/s
        else:
            self._set32(t, "MT_AUDIO_BLOCK_ALIGNMENT", AUDIO_CHANNELS * 2)
            self._set32(t, "MT_AUDIO_AVG_BYTES_PER_SECOND", AUDIO_RATE * AUDIO_CHANNELS * 2)
        return t

    def _add(self, out, inp, what: str) -> int:
        ct = self.ct
        index = ct.c_uint32()
        self._call(self.writer, 3, (ct.c_void_p, ct.POINTER(ct.c_uint32)), f"the {what}", out, ct.byref(index))
        self._call(self.writer, 4, (ct.c_uint32, ct.c_void_p, ct.c_void_p), f"the {what}", index.value, inp, None)
        return index.value

    def _write(self, stream: int, data: bytes, start: int, length: int) -> None:
        ct = self.ct
        buf, sample = ct.c_void_p(), ct.c_void_p()
        self._check(self.mfplat.MFCreateMemoryBuffer(len(data), ct.byref(buf)), "MFCreateMemoryBuffer")
        try:
            ptr = ct.c_void_p()
            self._call(buf, 3, (ct.POINTER(ct.c_void_p), ct.c_void_p, ct.c_void_p), "Lock", ct.byref(ptr), None, None)
            ct.memmove(ptr, data, len(data))
            self._call(buf, 4, (), "Unlock")
            self._call(buf, 6, (ct.c_uint32,), "SetCurrentLength", len(data))
            self._check(self.mfplat.MFCreateSample(ct.byref(sample)), "MFCreateSample")
            self._call(sample, 42, (ct.c_void_p,), "AddBuffer", buf)
            self._call(sample, 36, (ct.c_int64,), "SetSampleTime", start)
            self._call(sample, 38, (ct.c_int64,), "SetSampleDuration", length)
            self._call(self.writer, 6, (ct.c_uint32, ct.c_void_p), "WriteSample", stream, sample)
        finally:
            self._release(sample)
            self._release(buf)

    def video(self, frame: bytes) -> None:
        self._write(self.video_stream, frame, self.n_video * self.frame_100ns, self.frame_100ns)
        self.n_video += 1

    def audio(self, pcm: bytes) -> None:
        samples = len(pcm) // (AUDIO_CHANNELS * 2)
        start = self.n_audio * 10_000_000 // AUDIO_RATE
        self._write(self.audio_stream, pcm, start, samples * 10_000_000 // AUDIO_RATE)
        self.n_audio += samples

    def close(self) -> None:
        try:
            self._call(self.writer, 11, (), "Finalize")
        finally:
            for obj in reversed(self.objects):
                self._release(obj)
            self.objects = []
            self.mfplat.MFShutdown()


def make_encoder(path: Path, w: int, h: int, fps: int, audio: bool):
    return MfEncoder(path, w, h, fps, audio) if WINDOWS else GstEncoder(path, w, h, fps, audio)


# -- one recording ----------------------------------------------------------------------------------------------------

def _decode_jpeg(data: bytes, w: int, h: int) -> bytes:
    from PySide6.QtGui import QImage
    img = QImage.fromData(data, "JPEG").convertToFormat(QImage.Format.Format_RGB32)
    if img.isNull() or (img.width(), img.height()) != (w, h):
        raise RecordError("A JPEG part of the screen did not decode.")
    return bytes(img.constBits())


def _clock(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 3600}:{s // 60 % 60:02d}:{s % 60:02d}" if s >= 3600 else f"{s // 60}:{s % 60:02d}"


class Recording:
    """A guest's console going into an MP4 until stop(), its time limit, or the console closing (the guest stopped).

    open_console() → (WebSocket, password), as the console window uses; spice_config() → a SPICE ticket for the
    sound, or None for a guest without one."""

    def __init__(self, key: str, title: str, path: Path, open_console: Callable[[], tuple],
                 spice_config: Callable[[], dict] | None = None, max_seconds: int = DEFAULT_MAX_S, by: str = "you",
                 encoder: Callable | None = None, sound_note: str = ""):
        self.key, self.title, self.path, self.by = key, title, path, by
        self.open_console, self.spice_config = open_console, spice_config
        self.max_seconds = max(1, min(int(max_seconds), MAX_MAX_S))
        self.make_encoder = encoder or make_encoder
        self.sound_note = sound_note  # why there is no sound, or why it stopped
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.ready = threading.Event()
        self.done = threading.Event()
        self.ws = None
        self.client: RfbClient | None = None
        self.audio = None
        self.sound = False
        self.w = self.h = self.fps = 0
        self.fb = bytearray()
        self.fb_w = self.fb_h = 0
        self.cursor = None      # (hot_x, hot_y, w, h, argb) or None
        self.pointer = None     # (x, y): where the guest's pointer is, when the console says
        self.pcm = bytearray()
        self.primed = False
        self.audio_ok = True
        self.frames = 0
        self.behind = 0         # frames written late (the encoder could not keep up)
        self.started = 0.0
        self.ended = ""         # why it ended by itself
        self.error: Exception | None = None
        self.result: dict | None = None

    # -- starting --
    def start(self) -> None:
        ws, password = self.open_console()
        self.ws = ws
        try:
            ws.sock.settimeout(20)
            self.client = RfbClient(ws, password, TightDecoder(_decode_jpeg), 7, 6, pipelined=True)
            self.w, self.h, _ = self.client.handshake()
            ws.sock.settimeout(None)  # a console waits for the screen to change as long as it needs
        except Exception:
            ws.close()
            raise
        self.fps = fps_for(self.w, self.h)
        self.fb, self.fb_w, self.fb_h = bytearray(self.w * self.h * 4), self.w, self.h
        if self.spice_config is not None:
            from .spice_audio import SpiceAudio
            try:
                self.audio = SpiceAudio(self.spice_config(), self._audio_start, self._audio_data)
                self.audio.start()
                self.sound = True
            except Exception as e:
                self.audio, self.sound_note = None, f"no sound: {e}"
        threading.Thread(target=self._read, daemon=True, name=f"record-read-{self.key}").start()
        threading.Thread(target=self._pace, daemon=True, name=f"record-write-{self.key}").start()
        self.ready.wait(60)
        if self.error is not None:
            self._close_inputs()
            raise self.error if isinstance(self.error, RecordError) else RecordError(str(self.error))

    # -- the console's picture --
    def _read(self) -> None:
        try:
            while not self.stopping.is_set():
                ops = self.client.next_update()
                with self.lock:
                    for op in ops:
                        self._apply(op)
        except Exception as e:
            if not self.stopping.is_set():
                self.ended = f"the console closed ({e or 'the guest stopped?'})"

    def _apply(self, op: tuple) -> None:
        kind, w = op[0], self.fb_w
        if kind == "raw":
            _, x, y, rw, rh, data = op
            for row in range(rh):
                s = ((y + row) * w + x) * 4
                self.fb[s:s + rw * 4] = data[row * rw * 4:(row + 1) * rw * 4]
        elif kind == "copy":
            _, sx, sy, x, y, rw, rh = op
            rows = [bytes(self.fb[((sy + r) * w + sx) * 4:((sy + r) * w + sx + rw) * 4]) for r in range(rh)]
            for r, data in enumerate(rows):
                s = ((y + r) * w + x) * 4
                self.fb[s:s + rw * 4] = data
        elif kind == "size":
            self.fb_w, self.fb_h = op[1], op[2]
            self.fb = bytearray(self.fb_w * self.fb_h * 4)
            self.client.request_update(incremental=False)
        elif kind == "cursor":
            self.cursor = op[1:] if op[3] and op[4] else None
        elif kind == "pointer":
            self.pointer = (op[1], op[2])

    def _frame(self) -> bytes:
        """The picture now, at the recording's size, with the pointer drawn where the console says it is."""
        with self.lock:
            data, w, h, cursor, pointer = bytes(self.fb), self.fb_w, self.fb_h, self.cursor, self.pointer
        if (w, h) == (self.w, self.h) and (cursor is None or pointer is None):
            return data
        from PySide6.QtCore import QPoint, Qt
        from PySide6.QtGui import QImage, QPainter
        canvas = QImage(self.w, self.h, QImage.Format.Format_RGB32)
        canvas.fill(Qt.GlobalColor.black)
        src = QImage(data, w, h, w * 4, QImage.Format.Format_RGB32)
        p = QPainter(canvas)
        try:
            if (w, h) == (self.w, self.h):
                p.drawImage(0, 0, src)
                scale, ox, oy = 1.0, 0, 0
            else:  # the guest changed its resolution: fitted into the first one
                scaled = src.scaled(self.w, self.h, Qt.AspectRatioMode.KeepAspectRatio,
                                    Qt.TransformationMode.SmoothTransformation)
                scale = scaled.width() / max(1, w)
                ox, oy = (self.w - scaled.width()) // 2, (self.h - scaled.height()) // 2
                p.drawImage(ox, oy, scaled)
            if cursor is not None and pointer is not None:
                hx, hy, cw, ch, argb = cursor
                img = QImage(argb, cw, ch, cw * 4, QImage.Format.Format_ARGB32_Premultiplied)
                if scale != 1.0:
                    img = img.scaled(max(1, int(cw * scale)), max(1, int(ch * scale)))
                p.drawImage(QPoint(ox + int((pointer[0] - hx) * scale), oy + int((pointer[1] - hy) * scale)), img)
        finally:
            p.end()
        return bytes(canvas.constBits())

    # -- the sound --
    def _audio_start(self, channels: int, rate: int) -> None:
        if (channels, rate) != (AUDIO_CHANNELS, AUDIO_RATE):
            self.audio_ok = False
            self.sound_note = f"the guest's sound came as {channels} channels at {rate} Hz: left out"

    def _audio_data(self, pcm: bytes) -> None:
        if self.audio_ok:
            with self.lock:
                self.pcm.extend(pcm)

    def _audio_chunk(self, size: int) -> bytes:
        """Exactly `size` bytes of sound for one frame's time: the guest's, or silence where it has none yet."""
        second = AUDIO_RATE * AUDIO_CHANNELS * 2
        with self.lock:
            if len(self.pcm) > BACKLOG_S * second:  # fallen behind: the oldest goes
                del self.pcm[:len(self.pcm) - int(CUSHION_S * second) // 4 * 4]
            if not self.primed and len(self.pcm) >= CUSHION_S * second:
                self.primed = True
            if not self.primed:
                return bytes(size)
            out = bytes(self.pcm[:size])
            del self.pcm[:size]
            if len(out) < size:  # ran dry: silence, and a cushion again before it goes on
                self.primed = False
                out += bytes(size - len(out))
        if self.audio is not None and self.audio.ended and "stopped" not in self.sound_note:
            self.sound_note = f"the sound stopped at {_clock(self.frames / max(1, self.fps))}: {self.audio.ended}"
        return out

    # -- writing --
    def _pace(self) -> None:
        try:
            encoder = self.make_encoder(self.path, self.w, self.h, self.fps, self.sound)
        except Exception as e:
            self.error = e
            self.ready.set()
            self.done.set()
            return
        if self.sound and not getattr(encoder, "audio_on", True):
            self.sound, self.sound_note = False, getattr(encoder, "note", "") or "recorded without sound"
        self.started = time.time()
        self.ready.set()
        chunk = AUDIO_RATE * AUDIO_CHANNELS * 2 // self.fps
        t0 = time.monotonic()
        try:
            while not self.stopping.is_set():
                late = time.monotonic() - (t0 + self.frames / self.fps)
                if late < 0:
                    if self.stopping.wait(-late):
                        break
                elif late > 1.0:
                    self.behind += 1
                if self.sound:
                    encoder.audio(self._audio_chunk(chunk))
                encoder.video(self._frame())
                self.frames += 1
                if self.frames >= self.max_seconds * self.fps:
                    self.ended = f"its time limit ({_clock(self.max_seconds)})"
                    break
                if self.ended:
                    break
        except Exception as e:
            self.ended = f"it could not be written ({e})"
        finally:
            self._close_inputs()
            try:
                encoder.close()
            except Exception as e:
                self.error = e
            self._finish()

    def _close_inputs(self) -> None:
        self.stopping.set()
        if self.ws is not None:
            try:
                self.ws.close()
            except OSError:
                pass
        if self.audio is not None:
            self.audio.stop()

    def _finish(self) -> None:
        size = self.path.stat().st_size if self.path.exists() else 0
        self.result = {
            "file": str(self.path), "seconds": round(self.frames / max(1, self.fps), 1), "bytes": size,
            "size": f"{self.w}x{self.h}", "fps": self.fps, "sound": self.sound,
            **({"sound_note": self.sound_note} if self.sound_note else {}),
            "ended": self.ended or "stopped", **({"error": str(self.error)} if self.error else {}),
            **({"frames_late": self.behind} if self.behind else {}),
        }
        _ended(self)
        self.done.set()

    # -- for the app and for Claude --
    def stop(self, timeout: float = 200) -> dict:
        self.stopping.set()
        self.done.wait(timeout)
        if self.result is None:
            raise RecordError("The recording did not finish in time.")
        return self.result

    def status(self) -> dict:
        return {"guest": self.title, "file": str(self.path), "recording_for": _clock(self.frames / max(1, self.fps)),
                "size": f"{self.w}x{self.h}", "fps": self.fps, "sound": self.sound, "by": self.by,
                **({"sound_note": self.sound_note} if self.sound_note else {}),
                "limit": _clock(self.max_seconds)}


# -- the recordings of this app: one per guest ------------------------------------------------------------------------

_LOCK = threading.Lock()
_ACTIVE: dict[str, Recording] = {}
_FINISHED: dict[str, dict] = {}   # the last result of each guest, for a stop or status after it ended by itself
_NEWS: list[tuple[int, str, dict]] = []  # recordings that ended, numbered, for the app to say so (the last 50)
_NEWS_COUNT = 0


def start(rec: Recording) -> Recording:
    with _LOCK:
        if rec.key in _ACTIVE:
            raise RecordError(f"{_ACTIVE[rec.key].title} is already being recorded.")
        _ACTIVE[rec.key] = rec
    try:
        rec.start()
    except Exception:
        with _LOCK:
            if _ACTIVE.get(rec.key) is rec:
                del _ACTIVE[rec.key]
        raise
    return rec


def _ended(rec: Recording) -> None:
    global _NEWS_COUNT
    with _LOCK:
        if _ACTIVE.get(rec.key) is rec:
            del _ACTIVE[rec.key]
        _FINISHED[rec.key] = dict(rec.result, guest=rec.title)
        _NEWS_COUNT += 1
        _NEWS.append((_NEWS_COUNT, rec.key, _FINISHED[rec.key]))
        del _NEWS[:-50]


def get(key: str) -> Recording | None:
    with _LOCK:
        return _ACTIVE.get(key)


def active() -> list[Recording]:
    with _LOCK:
        return list(_ACTIVE.values())


def finished(key: str) -> dict | None:
    with _LOCK:
        return _FINISHED.get(key)


def news(after: int = 0) -> tuple[int, list[tuple[str, dict]]]:
    """The recordings that ended (by stop() or by themselves) after the one numbered `after`, and the number of the
    last one. Each reader keeps its own place, so one never takes the news from another."""
    with _LOCK:
        return _NEWS_COUNT, [(key, res) for n, key, res in _NEWS if n > after]


def pointer_moved(key: str, x: int, y: int) -> None:
    """Where this app just put the guest's pointer (console_click, the console window). QEMU sends a recording the
    pointer's shape but not where it is (measured 10/11/2026: no PointerPos), so the video draws it where the app's own
    clicks and moves put it."""
    rec = get(key)
    if rec is not None:
        with rec.lock:
            rec.pointer = (int(x), int(y))


def stop(key: str) -> dict:
    rec = get(key)
    if rec is None:
        done = finished(key)
        if done is None:
            raise RecordError("Nothing is being recorded there.")
        return done
    return rec.stop()


def stop_all() -> None:
    """When the app quits: every recording finished properly, so its file plays."""
    for rec in active():
        try:
            rec.stop(timeout=60)
        except RecordError:
            pass
