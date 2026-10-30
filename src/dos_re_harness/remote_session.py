"""Capture-scoped protocol ownership; no backend process or guest-state reuse."""
from __future__ import annotations

import sys


class RemoteConnections:
    def __init__(self, host, gdb_port, qmp_port, timeout, *, rsp_factory, qmp_factory):
        self._host = host
        self._gdb_port = gdb_port
        self._qmp_port = qmp_port
        self._timeout = timeout
        self._rsp_factory = rsp_factory
        self._qmp_factory = qmp_factory
        self._rsp = None
        self._qmp = []
        self._closed = False

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, kind, error, traceback):
        try:
            self.close()
        except BaseException as cleanup_error:
            if kind is None:
                raise
            print(f"protocol cleanup failed: {cleanup_error}", file=sys.stderr)
        return False

    def _require_open(self):
        if self._closed:
            raise RuntimeError("capture connections are closed")

    def open_rsp(self):
        self._require_open()
        if self._rsp is None:
            self._rsp = self._rsp_factory(self._host, self._gdb_port, self._timeout)
            for client in self._qmp:
                client.set_memory_reader(self._rsp.read_memory_chunked)
        return self._rsp

    def open_qmp(self):
        self._require_open()
        client = self._qmp_factory(self._host, self._qmp_port, self._timeout)
        self._qmp.append(client)
        # Explicit None also disables a legacy class-global reader before RSP exists.
        client.set_memory_reader(self._rsp.read_memory_chunked if self._rsp is not None else None)
        return client

    def close_qmp(self, client):
        for index, owned in enumerate(self._qmp):
            if owned is client:
                self._qmp.pop(index)
                client.set_memory_reader(None)
                client.close()
                return

    def close(self):
        if self._closed:
            return
        self._closed = True
        error = None
        # Preserve the driver's detach-before-final-QMP-close ordering.
        if self._rsp is not None:
            try:
                self._rsp.close()
            except BaseException as failure:
                error = failure
        for client in list(self._qmp):
            try:
                self.close_qmp(client)
            except BaseException as failure:
                if error is None:
                    error = failure
        self._rsp = None
        if error is not None:
            raise error
