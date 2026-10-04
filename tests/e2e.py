# End-to-end test for crystal-greeter, run by checks.<system>.e2e.
# Drives the greeter on tty1 through the NixOS test driver.
import re

SESSION_TIMEOUT = 90


def screen() -> str:
    return greeter.get_tty_text("1")


# Session supervisors join the user's logind scope after pam_open_session,
# so their lines are not attributed to crystal-greeter.service; match on the
# process name instead of the unit.
JOURNAL = "journalctl -t crystal-greeter -o cat"


def journal_count(event: str) -> str:
    return f"{JOURNAL} | grep -c '\"event\":\"{event}\"'"


def greeter_restarts() -> int:
    return int(greeter.succeed("systemctl show -p NRestarts --value crystal-greeter").strip())


def login(user: str, password: str) -> None:
    greeter.wait_until_tty_matches("1", "login:")
    # The greeter pauses on its first pass and flushes input before every
    # prompt; give it time to reach the read loop.
    greeter.sleep(3)
    greeter.send_chars(user + "\n")
    greeter.sleep(1)
    greeter.send_chars(password + "\n")


def choose(label_pattern: str) -> None:
    greeter.wait_until_tty_matches("1", "Choice")
    match = re.search(r"(\d+)\) [^\n]*" + label_pattern, screen())
    assert match, f"no menu entry matching {label_pattern!r}:\n{screen()}"
    greeter.send_chars(match.group(1) + "\n")


greeter.wait_for_unit("crystal-greeter.service")

with subtest("a wrong password is rejected without crashing the greeter"):
    login("test", "wrong")
    greeter.wait_until_tty_matches("1", "Login incorrect")
    assert greeter_restarts() == 0, "greeter restarted after a failed login"

with subtest("a failed ssh session returns to a single greeter"):
    login("test", "test")
    choose(r"ssh")
    greeter.sleep(1)
    greeter.send_chars("nonexistent.invalid\n")
    greeter.wait_until_succeeds(f"[ $({journal_count('session.ssh.ended')}) -ge 1 ]", timeout=SESSION_TIMEOUT)
    greeter.wait_until_tty_matches("1", "login:")
    greeter.succeed("[ $(pgrep -c -x crystal-greeter) -eq 1 ]")
    greeter.fail("pgrep -x ssh")

with subtest("x11 sessions free their slot and give the VT back"):
    # More logins than there are slots (5): a leaked slot would show up as
    # "All session slots in use".
    for n in range(1, 7):
        login("test", "test")
        choose(r"\(X11\)")
        greeter.wait_until_succeeds(f"[ $({journal_count('session.x11.starting')}) -ge {n} ]", timeout=SESSION_TIMEOUT)
        greeter.wait_until_succeeds(
            f"(pkill -u test || true) && [ $({journal_count('session.x11.ended')}) -ge {n} ]",
            timeout=SESSION_TIMEOUT,
        )
        assert "All session slots in use" not in screen(), screen()
        greeter.succeed("[ \"$(stat -c '%U:%G %a' /dev/tty3)\" = 'root:tty 620' ]")

with subtest("the greeter never crashed"):
    assert greeter_restarts() == 0, "greeter restarted"
    greeter.fail(f"{JOURNAL} | grep -q 'Unhandled exception'")
