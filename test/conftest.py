"""pytest fixtures for ndpi-observe tests."""

import os
import signal
import subprocess
import time

import pytest

SRC_DIR   = os.environ.get("SRC_DIR", "/src")
NDPID     = os.path.join(SRC_DIR, "ndpid")
NDPICTL   = os.path.join(SRC_DIR, "ndpictl")
CLI_SOCK  = "/run/ndpid/cli.sock"
IFACE     = "veth-obs0"
PEER      = "veth-obs1"


def _run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check,
                          capture_output=True, text=True)


@pytest.fixture(scope="session")
def ndpid():
    """Start ndpid on a veth pair for the entire test session."""
    # Clean up any leftovers
    _run(f"ip link del {IFACE} 2>/dev/null", check=False)
    _run(f"rm -f {CLI_SOCK}", check=False)

    # Create veth pair
    _run(f"ip link add {IFACE} type veth peer name {PEER}")
    _run(f"ip link set {IFACE} up")
    _run(f"ip link set {PEER}  up")
    _run(f"ip addr add 10.99.0.1/24 dev {IFACE}")
    _run(f"ip addr add 10.99.0.2/24 dev {PEER}")

    # Start ndpid
    proc = subprocess.Popen(
        [NDPID, "-i", IFACE, "-p", "19197"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )

    # Wait for CLI socket
    for _ in range(100):
        if os.path.exists(CLI_SOCK):
            break
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            pytest.fail(f"ndpid exited early: rc={proc.returncode}\n{out}")
        time.sleep(0.1)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
        pytest.fail(f"ndpid failed to create CLI socket at {CLI_SOCK}")

    class Handle:
        def __init__(self, proc):
            self.proc = proc

        def ctl(self, cmd):
            env = os.environ.copy()
            env["NDPID_SOCKET"] = CLI_SOCK
            r = subprocess.run(
                [NDPICTL] + cmd.split(),
                capture_output=True, text=True, timeout=10, env=env
            )
            return r.returncode, r.stdout, r.stderr

    handle = Handle(proc)
    try:
        yield handle
    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass
        _run(f"ip link del {IFACE} 2>/dev/null", check=False)
        _run(f"rm -f {CLI_SOCK}", check=False)
