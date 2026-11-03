"""Tier 5: Adversarial Empirical Stress Tests - Phase 0 Deliverables.

Evaluates:
1. Concurrency & Mutex: Multi-instance simultaneous startup race conditions.
2. IPC Throughput & Stress: Rapid sequential and parallel `--toggle` bursts.
3. Fault Injection & Resilience: Abrupt secondary socket drops, garbage bytes, huge payloads.
4. Crash & Recovery: Stale/orphan socket detection and self-healing.
5. CLI Boundary Handling: Flag combinations, unknown options, oversize args.
6. Local DoS Vulnerability: Detection of blocking reads on unclosed client streams.
7. Window & Configuration Integrity: Rigorous boundary checks against PROJECT.md.
"""

import json
import os
import signal
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Generator, Tuple

import pytest

from tests.e2e.oracle.config_oracle import ConfigOracle


def get_socket_path() -> Path:
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir and Path(runtime_dir).exists():
        return Path(runtime_dir) / "authdesk_com_rod_authdesk.sock"
    return Path("/tmp") / "authdesk_com_rod_authdesk.sock"


def cleanup_socket():
    sock = get_socket_path()
    if sock.exists():
        try:
            sock.unlink()
        except OSError:
            pass


@pytest.fixture
def running_primary(authdesk_binary: Path) -> Generator[subprocess.Popen, None, None]:
    """Spawns an isolated primary AuthDesk daemon in hidden mode and cleans up on teardown."""
    if not authdesk_binary or not authdesk_binary.exists():
        pytest.skip("AuthDesk binary not found")

    cleanup_socket()
    proc = subprocess.Popen(
        [str(authdesk_binary), "--hidden"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Allow daemon time to bind IPC socket
    time.sleep(0.4)
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        cleanup_socket()


@pytest.mark.tier(5)
@pytest.mark.milestone("M0")
class TestPhase0Adversarial:
    """Empirical adversarial test suite for Phase 0."""

    def test_window_configuration_boundaries(self, tauri_conf_path: Path):
        """Boundary stress: Validates exact window attributes in tauri.conf.json."""
        assert tauri_conf_path.exists(), "tauri.conf.json missing"
        with open(tauri_conf_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        windows = data.get("app", {}).get("windows", [])
        palette = next((w for w in windows if w.get("label") == "palette"), None)
        assert palette is not None, "palette window missing"

        # Explicit value boundary assertions
        assert palette.get("width") == 420
        assert palette.get("height") == 560
        assert palette.get("minWidth") == 420
        assert palette.get("maxWidth") == 420
        assert palette.get("minHeight") == 560
        assert palette.get("maxHeight") == 560
        assert palette.get("resizable") is False
        assert palette.get("decorations") is False
        assert palette.get("transparent") is True
        assert palette.get("alwaysOnTop") is True
        assert palette.get("skipTaskbar") is True
        assert palette.get("center") is True
        assert palette.get("visible") is False

    def test_concurrent_primary_launches_mutex(self, authdesk_binary: Path):
        """Stress: Spawns 5 primary instances at the same millisecond to test mutex race condition."""
        if not authdesk_binary or not authdesk_binary.exists():
            pytest.skip("AuthDesk binary not found")

        cleanup_socket()
        procs = []
        try:
            with ThreadPoolExecutor(max_workers=5) as ex:
                futures = [
                    ex.submit(
                        lambda: subprocess.Popen(
                            [str(authdesk_binary), "--hidden"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                    )
                    for _ in range(5)
                ]
                procs = [f.result() for f in futures]

            time.sleep(1.0)
            alive = [p for p in procs if p.poll() is None]
            dead = [p for p in procs if p.poll() is not None]

            # Exactly one primary must hold the single-instance lock
            assert len(alive) == 1, f"Expected exactly 1 alive primary, found {len(alive)}"
            assert len(dead) == 4, f"Expected 4 processes to exit, found {len(dead)}"
        finally:
            for p in procs:
                if p.poll() is None:
                    p.terminate()
                    p.wait(timeout=2.0)
            cleanup_socket()

    def test_rapid_consecutive_toggles(self, authdesk_binary: Path, running_primary: subprocess.Popen):
        """Stress: Burst of 20 sequential CLI --toggle invocations."""
        for i in range(20):
            res = subprocess.run(
                [str(authdesk_binary), "--toggle"],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            assert res.returncode == 0, f"Toggle {i} failed with return code {res.returncode}: {res.stderr}"
        assert running_primary.poll() is None, "Primary crashed during sequential toggle burst"

    def test_concurrent_secondary_toggles(self, authdesk_binary: Path, running_primary: subprocess.Popen):
        """Stress: 20 simultaneous parallel --toggle CLI invocations."""
        def invoke_toggle(idx: int) -> Tuple[int, int, str]:
            res = subprocess.run(
                [str(authdesk_binary), "--toggle"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            return idx, res.returncode, res.stderr

        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(invoke_toggle, range(20)))

        failures = [r for r in results if r[1] != 0]
        assert len(failures) == 0, f"Concurrent toggles failed: {failures}"
        assert running_primary.poll() is None, "Primary crashed during concurrent toggle burst"

    def test_primary_survives_abrupt_disconnect(self, authdesk_binary: Path, running_primary: subprocess.Popen):
        """Fault injection: Client connects to IPC socket and abruptly drops without data."""
        sock_path = str(get_socket_path())
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        s.close()
        time.sleep(0.1)

        assert running_primary.poll() is None, "Primary crashed on abrupt socket drop"

        # Verify it still responds to subsequent --toggle
        res = subprocess.run(
            [str(authdesk_binary), "--toggle"],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        assert res.returncode == 0

    def test_primary_survives_huge_payload(self, authdesk_binary: Path, running_primary: subprocess.Popen):
        """Fault injection: Sends 1 MB payload to IPC socket."""
        sock_path = str(get_socket_path())
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        s.sendall(b"A" * (1024 * 1024) + b"\n")
        resp = s.recv(1024)
        s.close()

        assert running_primary.poll() is None, "Primary crashed on 1MB payload"
        assert b"ACK" in resp

    def test_primary_survives_stale_socket_recovery(self, authdesk_binary: Path, running_primary: subprocess.Popen):
        """Fault recovery: Kills primary via SIGKILL and verifies new primary cleans stale socket."""
        running_primary.send_signal(signal.SIGKILL)
        running_primary.wait()

        sock_path = get_socket_path()
        assert sock_path.exists(), "Stale socket must exist after SIGKILL"

        # Spawn new primary over the stale socket
        new_primary = subprocess.Popen(
            [str(authdesk_binary), "--hidden"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.5)
        try:
            assert new_primary.poll() is None, "New primary failed to start over stale socket"

            # Verify toggle works on new primary
            res = subprocess.run(
                [str(authdesk_binary), "--toggle"],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            assert res.returncode == 0
        finally:
            if new_primary.poll() is None:
                new_primary.terminate()
                new_primary.wait(timeout=2.0)

    def test_cli_flag_combinations(self, authdesk_binary: Path, running_primary: subprocess.Popen):
        """Boundary: Checks combined flags and extreme argument lengths."""
        # 1. Combined --toggle --hidden
        res = subprocess.run(
            [str(authdesk_binary), "--toggle", "--hidden"],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        assert res.returncode == 0

        # 2. Unknown flags combined with --toggle
        res = subprocess.run(
            [str(authdesk_binary), "--toggle", "--unknown-flag"],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        assert res.returncode == 0

        # 3. Oversize argument (50KB)
        res = subprocess.run(
            [str(authdesk_binary), "--toggle", "X" * 50000],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        assert res.returncode == 0

    def test_cli_toggle_without_primary(self, authdesk_binary: Path):
        """Boundary: Invoking --toggle when no primary exists exits cleanly with code 0."""
        cleanup_socket()
        res = subprocess.run(
            [str(authdesk_binary), "--toggle"],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        assert res.returncode == 0
        assert "Advertencia:" in res.stderr

    def test_dos_vulnerability_hanging_client(self, authdesk_binary: Path, running_primary: subprocess.Popen):
        """Vulnerability probe: Detects whether an unclosed client stream blocks the IPC listener.
        
        This test documents the empirical vulnerability: if a client connects and sends partial
        data without a newline, the single-threaded listener thread blocks in `read_line`
        without timeout, causing subsequent `--toggle` calls to hang.
        """
        sock_path = str(get_socket_path())
        hanging_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        hanging_sock.connect(sock_path)
        hanging_sock.sendall(b"HANGING_CLIENT_NO_NEWLINE")

        # Now test if a concurrent toggle request can proceed or times out
        timed_out = False
        try:
            subprocess.run(
                [str(authdesk_binary), "--toggle"],
                capture_output=True,
                text=True,
                timeout=1.5,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            hanging_sock.close()

        # The test passes if we empirically observed the blocking behavior,
        # confirming the vulnerability.
        assert timed_out is True, "Expected secondary --toggle to time out while primary is blocked by hanging client"
