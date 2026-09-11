"""Smoke tests — binary exists, attaches to interface, CLI responds."""

import os
import subprocess

import pytest

SRC_DIR  = os.environ.get("SRC_DIR", "/src")
NDPID    = os.path.join(SRC_DIR, "ndpid")
NDPICTL  = os.path.join(SRC_DIR, "ndpictl")


def test_ndpid_binary_exists():
    assert os.path.isfile(NDPID), f"ndpid not found at {NDPID}"
    assert os.access(NDPID, os.X_OK), "ndpid is not executable"


def test_ndpictl_binary_exists():
    assert os.path.isfile(NDPICTL), f"ndpictl not found at {NDPICTL}"
    assert os.access(NDPICTL, os.X_OK), "ndpictl is not executable"


def test_show_version(ndpid):
    rc, out, _ = ndpid.ctl("show version")
    assert rc == 0
    assert "ndpi-observe" in out


def test_show_stats(ndpid):
    rc, out, _ = ndpid.ctl("show stats")
    assert rc == 0
    assert "flows created" in out
    assert "packets scanned" in out


def test_show_applications_no_traffic(ndpid):
    rc, out, _ = ndpid.ctl("show applications top 5")
    assert rc == 0
    # Either the header or "no classified flows" message
    assert "Application" in out or "no classified" in out


def test_show_flows_no_traffic(ndpid):
    rc, out, _ = ndpid.ctl("show flows count 5")
    assert rc == 0
    assert "Src IP" in out or "no active" in out


def test_unknown_command(ndpid):
    rc, out, _ = ndpid.ctl("bogus command")
    assert rc == 0
    assert "unknown command" in out
