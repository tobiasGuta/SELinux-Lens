"""Coordinate lab logins inside the disposable KVM guest."""

import json
import subprocess
import time
from pathlib import Path

ROOT = Path("/run/selinux-lens-sessions")


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def wait_for(check, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.2)
    raise AssertionError("Timed out waiting for guest session state")


def status(role):
    path = ROOT / (role + ".json")
    return json.loads(path.read_text()) if path.exists() else {}


def paired(active, inactive):
    first, second = status(active), status(inactive)
    if (
        first.get("active") is True and first.get("bound_session") == first.get("id")
        and second.get("active") is False and second.get("bound_session") is None
    ):
        return first, second
    return None


def show(case, record):
    print("SESSION CHECK", case, json.dumps(record, sort_keys=True), flush=True)


def main():
    try:
        for tty in ("7", "8"):
            command("/usr/bin/systemctl", "start", "--no-block", "getty@tty" + tty + ".service")
            command("/usr/bin/chvt", tty)
            wait_for(lambda tty=tty: status("tty" + tty).get("active"))
        active, inactive = wait_for(lambda: paired("tty8", "tty7"))
        for case, value in (("active local", active), ("inactive local", inactive)):
            show(case, value)
        assert active["id"] != inactive["id"] and active["uid"] == inactive["uid"]
        assert not active["remote"] and not inactive["remote"]
        assert active["seat"] == inactive["seat"] == "seat0"
        assert not any(s["authorized"] for s in (active, inactive))
        command("/usr/bin/systemctl", "start", "--no-block", "getty@tty9.service")
        remote = wait_for(lambda: status("tty9"))
        show("PAM-marked remote", remote)
        assert remote["remote"] and remote["bound_session"] is None and not remote["authorized"]
        assert remote["uid"] == active["uid"] and remote["id"] not in {active["id"], inactive["id"]}
        command("/usr/bin/chvt", "9")
        remote_active = wait_for(lambda: (record if (record := status("tty9")).get("active") else None))
        show("active PAM-marked remote", remote_active)
        assert remote_active["remote"] and remote_active["bound_session"] is None

        command("/usr/bin/chvt", "7")
        switched, switched_inactive = wait_for(lambda: paired("tty7", "tty8"))
        assert switched["id"] == inactive["id"] and switched_inactive["id"] == active["id"]
        show("active after switch", switched)
        show("inactive after switch", switched_inactive)

        (ROOT / "try-auth").touch()
        authentication = wait_for(lambda: status("authentication"), timeout=40)
        show("live Polkit authentication and cancellation", authentication)
        assert "error" not in authentication, authentication

        command("/usr/bin/loginctl", "terminate-session", switched_inactive["id"])
        destination = switched_inactive["connection"]

        def disconnected():
            result = command(
                "/usr/bin/busctl", "--system", "call", "org.freedesktop.DBus",
                "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner", "s", destination,
            )
            return result == "b false"

        wait_for(disconnected)
        print("SESSION CHECK terminated session lost its system-bus connection", flush=True)
    finally:
        (ROOT / "stop").touch()
        command("/usr/bin/systemctl", "stop", "--no-block", "getty@tty7", "getty@tty8", "getty@tty9")


if __name__ == "__main__":
    main()
