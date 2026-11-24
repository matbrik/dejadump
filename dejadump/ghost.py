"""Lifecycle for a disposable idalib analysis worker (IDA-only caller)."""

from __future__ import annotations

import json
import os
import queue
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor


def _backup_store(store, destination: str) -> None:
    dst = sqlite3.connect(destination)
    try:
        if store.path != ":memory:" and os.path.exists(store.path):
            source = sqlite3.connect(store.path)
            try:
                source.backup(dst)
            finally:
                source.close()
        else:
            store.conn.backup(dst)
    finally:
        dst.close()


class GhostWorkerClient:
    """One lazily-created worker; callers may create up to their desired pool size."""

    def __init__(self, store, python_executable: str, *, template_idb=None,
                 template_sidecar=None):
        self._tmp = tempfile.mkdtemp(prefix="dejadump-ghost-")
        self._idb = os.path.join(self._tmp, "worker.i64")
        self._sidecar = os.path.join(self._tmp, "worker.dejadump.db")
        if template_idb and template_sidecar:
            shutil.copy2(template_idb, self._idb)
            shutil.copy2(template_sidecar, self._sidecar)
        else:
            import ida_loader
            if not ida_loader.save_database(self._idb, getattr(ida_loader, "DBFL_TEMP", 0)):
                shutil.rmtree(self._tmp, ignore_errors=True)
                raise RuntimeError("could not create the disposable worker database")
            _backup_store(store, self._sidecar)
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "worker.py")
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        # The worker's log goes to a file: an undrained stderr pipe would fill up
        # and block the worker mid-request.
        self._log_path = os.path.join(self._tmp, "worker.log")
        self._log = open(self._log_path, "w", encoding="utf-8", errors="replace")
        self._proc = subprocess.Popen(
            [python_executable, script, self._idb, self._sidecar],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._log,
            text=True, bufsize=1, env=env,
        )
        # A reader thread instead of select(): pipes are not selectable on Windows.
        self._lines: queue.Queue = queue.Queue()
        self._reader = threading.Thread(target=self._pump, name="dejadump-idalib-reader",
                                        daemon=True)
        self._reader.start()
        self._next_id = 1
        self._lock = threading.RLock()
        self.capabilities = {}
        capabilities = self.request("capabilities")
        if not capabilities.get("ok"):
            self.close()
            raise RuntimeError(capabilities.get("error", "idalib worker failed to start"))
        self.capabilities = capabilities

    def _pump(self) -> None:
        try:
            for line in self._proc.stdout:
                self._lines.put(line)
        finally:
            self._lines.put("")  # end of stream

    def _log_tail(self) -> str:
        try:
            self._log.flush()
            with open(self._log_path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()[-1000:]
        except OSError:
            return ""

    def request(self, op: str, *, timeout: float = 300.0, cancelled=None, **params) -> dict:
        with self._lock:
            if self._proc.poll() is not None:
                raise RuntimeError("idalib worker exited: %s" % self._log_tail())
            request = {"id": self._next_id, "op": op, **params}
            self._next_id += 1
            try:
                self._proc.stdin.write(json.dumps(request) + "\n")
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                raise RuntimeError("idalib worker exited: %s" % self._log_tail())
            deadline = time.monotonic() + timeout
            while True:
                if cancelled and cancelled():
                    self._proc.terminate()
                    raise InterruptedError("idalib request cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._proc.terminate()
                    raise TimeoutError("idalib worker timed out during %s" % op)
                try:
                    raw = self._lines.get(timeout=min(0.1, remaining))
                    break
                except queue.Empty:
                    if self._proc.poll() is not None and self._lines.empty():
                        raise RuntimeError("idalib worker exited: %s" % self._log_tail())
            if not raw:
                raise RuntimeError("idalib worker closed its response stream: %s" %
                                   self._log_tail())
            response = json.loads(raw)
            if response.get("id") != request["id"]:
                raise RuntimeError("idalib worker protocol desynchronised")
            return response

    def render(self, epoch: int, kind: str, start: int, end: int, cancelled=None) -> dict:
        with self._lock:
            prepared = self.request("prepare_epoch", epoch=epoch, cancelled=cancelled)
            if not prepared.get("ok"):
                return prepared
            return self.request("render_" + kind, start=start, end=end, cancelled=cancelled)

    def cancel(self) -> None:
        proc = getattr(self, "_proc", None)
        if proc is not None and proc.poll() is None:
            proc.terminate()

    def close(self) -> None:
        proc = getattr(self, "_proc", None)
        if proc is not None and proc.poll() is None:
            try:
                self.request("shutdown", timeout=10)
                proc.wait(timeout=5)
            except Exception:
                proc.terminate()
        if proc is not None:
            for stream in (proc.stdin, proc.stdout):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        log = getattr(self, "_log", None)
        if log is not None:
            log.close()
        shutil.rmtree(getattr(self, "_tmp", ""), ignore_errors=True)


class GhostWorkerPool:
    """Bounded, crash-recovering pool of disposable idalib workers."""

    def __init__(self, store, python_executable: str, size: int = 2):
        import ida_loader

        self.store = store
        self.python_executable = python_executable
        self.size = max(1, min(int(size), 4))
        self._template_tmp = tempfile.mkdtemp(prefix="dejadump-template-")
        self._template_idb = os.path.join(self._template_tmp, "template.i64")
        self._template_sidecar = os.path.join(self._template_tmp, "template.dejadump.db")
        if not ida_loader.save_database(
            self._template_idb, getattr(ida_loader, "DBFL_TEMP", 0)
        ):
            shutil.rmtree(self._template_tmp, ignore_errors=True)
            raise RuntimeError("could not create the clean worker template")
        _backup_store(store, self._template_sidecar)
        self._workers = []
        try:
            for _ in range(self.size):
                self._workers.append(GhostWorkerClient(
                    store, python_executable, template_idb=self._template_idb,
                    template_sidecar=self._template_sidecar))
        except Exception:
            for worker in self._workers:
                worker.close()
            shutil.rmtree(self._template_tmp, ignore_errors=True)
            raise
        self._next = 0
        self._lock = threading.Lock()

    @property
    def capabilities(self) -> dict:
        return dict(self._workers[0].capabilities) if self._workers else {}

    def _slot(self):
        with self._lock:
            index = self._next % len(self._workers)
            self._next += 1
        return index, self._workers[index]

    def _replace(self, index: int):
        try:
            self._workers[index].close()
        finally:
            self._workers[index] = GhostWorkerClient(
                self.store, self.python_executable, template_idb=self._template_idb,
                template_sidecar=self._template_sidecar)
        return self._workers[index]

    def render(self, epoch: int, kind: str, start: int, end: int, cancelled=None) -> dict:
        index, worker = self._slot()
        try:
            return worker.render(epoch, kind, start, end, cancelled)
        except InterruptedError:
            # A cancelled request terminated its worker; replace it for next time.
            self._replace(index)
            raise
        except Exception:
            worker = self._replace(index)
            return worker.render(epoch, kind, start, end, cancelled)

    def render_many(self, requests: list[tuple[int, str, int, int]]) -> list[dict]:
        """Render up to the pool width concurrently, preserving request order."""
        with ThreadPoolExecutor(max_workers=self.size,
                                thread_name_prefix="dejadump-idalib") as executor:
            futures = [executor.submit(self.render, *request) for request in requests]
            return [future.result() for future in futures]

    def cancel(self) -> None:
        for worker in self._workers:
            worker.cancel()

    def close(self) -> None:
        for worker in self._workers:
            worker.close()
        self._workers = []
        shutil.rmtree(getattr(self, "_template_tmp", ""), ignore_errors=True)
