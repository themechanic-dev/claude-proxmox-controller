"""Runs blocking work (API calls, Wake-on-LAN) off the window's thread and hands the answer back to it.

    runner.run(lambda: pve.guests(), on_done)      # on_done(result, error) runs on the GUI thread

The callbacks stay on the GUI thread (the worker only carries a number): a widget must never lose its last reference
on a worker thread, because Qt would then destroy it there — that crashed the app (measured with the console).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from PySide6.QtCore import QObject, Signal

Done = Callable[[Any, Exception | None], None]
_ALIVE: list["Runner"] = []  # runners are never destroyed by a worker thread finishing its last job


class Runner(QObject):
    _finished = Signal(int, object, object)  # job number, result, error — delivered on the GUI thread

    def __init__(self, workers: int = 4):
        super().__init__()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pve")
        self._finished.connect(self._deliver)
        self._callbacks: dict[int, Done] = {}
        self._next = 0
        self.closed = False
        _ALIVE.append(self)

    def run(self, fn: Callable[[], Any], done: Done | None = None) -> None:
        if self.closed:
            return
        self._next += 1
        number = self._next
        if done is not None:
            self._callbacks[number] = done
        finished = self._finished

        def job():
            try:
                result, error = fn(), None
            except Exception as e:  # handed to the window, which shows it
                result, error = None, e
            if not self.closed:
                finished.emit(number, result, error)

        self._pool.submit(job)

    def _deliver(self, number: int, result, error) -> None:
        done = self._callbacks.pop(number, None)
        if done is not None and not self.closed:
            done(result, error)

    def close(self) -> None:
        self.closed = True
        self._callbacks.clear()
        self._pool.shutdown(wait=False, cancel_futures=True)
