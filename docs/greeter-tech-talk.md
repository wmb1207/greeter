---
marp: true
title: "greeter: a custom Crystal-powered TTY greeter"
paginate: true
theme: default
---

# greeter

## the custom Crystal-powered TTY login greeter

Minimal Linux login UX, built as a native Crystal systems tool.

---

# Why This Exists

- Boots straight into a clean TTY UI
- Authenticates real system users through PAM
- Starts X11, Wayland, SSH, reboot, shutdown, and Moonlight flows
- Keeps the greeter small enough to understand end to end
- Avoids a full display manager stack when the machine only needs a sharp login launcher

---

# What It Does

1. Draws a TTY login screen
2. Reads username and hidden password input
3. Authenticates with PAM's `login` service
4. Discovers installed `.desktop` sessions
5. Shows a combined dynamic and static menu
6. Forks, drops privileges, and execs the selected session
7. Returns to the login prompt after sessions exit

---

# Tech Stack

- Language: Crystal
- System interfaces: LibC FFI and Linux-PAM FFI
- Runtime target: native Linux binary
- Packaging: Nix flake and NixOS module
- Service manager: systemd
- Config format: YAML at `/etc/greeter.conf`
- Logging: JSONL to stderr, collected by journald
- UI: raw ANSI terminal control on a Linux console

---

# Repository Map

```text
src/greeter.cr          main loop, login flow, menu dispatch
src/auth.cr             PAM authentication
src/sessions.cr         X11, Wayland, SSH session launch
src/terminal.cr         TTY rendering and input
src/config.cr           YAML config and menu parsing
src/platform.cr         Linux/FreeBSD-ish paths and machine data
src/libs.cr             PAM and LibC bindings
src/session_tracker.cr  X11 child tracking and VT allocation
src/logger.cr           JSONL operational logs
```

---

# Core Design Choice

The parent greeter stays privileged.

The launched session does not.

```text
root greeter
  |
  | authenticate user with PAM
  |
  +-- fork child
        |
        +-- initgroups
        +-- setgid
        +-- setuid
        +-- exec user session
```

This preserves the greeter's ability to authenticate the next login.

---

# Authentication

- Uses PAM through custom Crystal FFI bindings
- Starts a `login` PAM transaction
- Supplies the password through a PAM conversation callback
- Runs both `pam_authenticate` and `pam_acct_mgmt`
- Returns a live PAM handle so session launch can call `pam_open_session`
- Looks up the authenticated user with `getpwnam`

Speaker note: the password is held in memory for the PAM callback and is not logged.

---

# Privilege Drop

Order matters:

1. `initgroups`
2. `setgid`
3. `setuid`

After `setuid`, the process can no longer safely adjust groups.

The code treats this as a hard session-launch boundary: if privilege dropping fails, the child exits instead of running user code as root.

---

# Session Discovery

The greeter scans configured directories:

- `xsessions`
- `wayland-sessions`

It parses `.desktop` files for:

- `Name=`
- `Exec=`

Then it removes desktop field codes such as `%u` and builds menu labels like:

```text
Openbox (X11)
niri (Wayland)
```

---

# X11 Launch Model

X11 sessions are launched on a pool of extra VTs.

```text
greeter tty1
  |
  +-- supervisor child, still root
        |
        +-- pam_open_session
        +-- worker child
              |
              +-- chown tty
              +-- drop privileges
              +-- exec startx <wm> -- :display vtN
        |
        +-- wait
        +-- pam_close_session
```

Current VT pool: `tty3` through `tty7`.

---

# Why X11 Gets a Supervisor

The greeter parent should not own the user's graphical PAM session.

So the X11 supervisor child owns:

- `pam_open_session`
- the worker process
- `pam_close_session`

The parent records the supervisor PID and immediately returns to the login prompt.

Result: multiple X11 sessions can be active while the greeter keeps accepting logins.

---

# Wayland Launch Model

Wayland sessions run directly on the configured greeter VT.

```text
greeter
  |
  +-- pam_open_session
  +-- fork child
        |
        +-- chown tty
        +-- ensure runtime dir when needed
        +-- drop privileges
        +-- exec compositor/session
  |
  +-- wait
  +-- pam_close_session
```

This path blocks the greeter until the Wayland session exits.

---

# Other Actions

Static menu entries are config-driven:

- `exit`
- `reboot`
- `shutdown`
- `ssh`
- `moonlight`

Moonlight is treated as a TTY-native streaming session:

- finds `moonlight` or `moonlight-qt`
- sets `SDL_VIDEODRIVER=kmsdrm`
- opens a PAM session for logind and `/run/user/<uid>`
- runs without X

---

# Runtime Environment

Sessions launch with a cleared environment and explicit variables:

- identity: `HOME`, `USER`, `LOGNAME`, `SHELL`
- path: user profile, Nix profile, system profile, wrappers
- logind: `XDG_SESSION_TYPE`, `XDG_SESSION_CLASS`, `XDG_SEAT`, `XDG_VTNR`
- user services: `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`
- audio: `PULSE_SERVER`

This is one of the most important compatibility pieces.

---

# TTY User Interface

- ANSI escape sequences draw the screen
- Layout adapts to terminal width
- Password input uses noncanonical mode and hidden echo
- `Ctrl+L` toggles console keymap between `us` and `dvorak`
- Right-side panel shows machine details:
  - host
  - OS
  - kernel
  - model
  - CPU
  - memory
  - disks

---

# Config Surface

```yaml
title: "WMB Greeter"
vt: 1
seat: seat0
default_keyboard_layout: us

xsession_dirs:
  - /run/current-system/sw/share/xsessions

wayland_session_dirs:
  - /run/current-system/sw/share/wayland-sessions

menu:
  - action: exit
  - action: reboot
  - action: shutdown
  - action: ssh
  - action: moonlight
    host: desktop.wmb.arpa
```

Invalid or missing config falls back to compiled defaults.

---

# Packaging And Deployment

The flake provides:

- a release package
- a NixOS module
- a development shell
- a test VM

The NixOS module:

- writes `/etc/greeter.conf`
- installs a setuid-root wrapper
- disables `getty` on the chosen VT
- runs `crystal-greeter` as a systemd service
- sends stderr logs to journald
- quiets kernel and service chatter on the greeter TTY

---

# Observability

Logs are structured JSONL:

```json
{
  "timestamp": "2026-09-06T12:00:00.000Z",
  "level": "info",
  "event": "session.x11.starting",
  "message": "Starting X11 session",
  "fields": {
    "username": "alice",
    "vt": 3,
    "display": 0
  }
}
```

Debugging entry point:

```sh
journalctl -u crystal-greeter.service -o cat
```

---

# Testing Today

Current specs cover:

- JSONL logger shape and severity helpers
- logger failure isolation
- keyboard layout config parsing
- fallback behavior for invalid keyboard layouts

The flake also includes a NixOS VM with a test user and installed X11/Wayland session packages.

---

# Limitations

- Linux is the practical target; FreeBSD helpers exist, but PAM/session integration is Linux-centric
- NixOS assumptions are baked into paths, packaging, wrappers, and service setup
- The binary must run setuid-root or root
- PAM bindings are hand-written FFI, so ABI correctness matters
- `.desktop` parsing is intentionally minimal
- Wayland, SSH, and Moonlight sessions block the greeter while active
- X11 concurrency is capped at five sessions: `tty3` to `tty7`

---

# More Limitations

- Static config is loaded only at startup
- No graphical accessibility features
- No localization
- No username chooser or user avatar model
- No account/session policy UI beyond what PAM and the menu expose
- No automated integration tests for real PAM, logind, TTY ownership, Xorg, or Wayland compositor behavior
- Terminal rendering depends on a real console behaving like expected

---

# Security Boundaries

Strong parts:

- no shell for X session execution
- explicit privilege drop before user session exec
- environment is cleared and rebuilt
- PAM account management is checked
- operational logs avoid passwords

Risk areas:

- root/setuid attack surface
- direct TTY ownership changes
- manual C ABI bindings
- session commands inherited from `.desktop` files and local config

---

# Architecture In One Slide

```text
TTY + ANSI UI
    |
Config + session discovery
    |
PAM auth + passwd lookup
    |
Menu dispatch
    |
    +-- X11: supervisor + VT pool + startx
    +-- Wayland: direct compositor exec on greeter VT
    +-- SSH: user shell command on TTY
    +-- Moonlight: KMS/DRM streaming session
    +-- Power actions: systemctl
    |
JSONL logs to journald
```

---

# Talk Track

1. Start with the problem: display managers are big, this machine needed a focused launcher.
2. Show why Crystal is a good fit: native binary, typed, readable, FFI-friendly.
3. Explain the root parent and unprivileged child boundary.
4. Walk through PAM, logind, environment, and VT handling.
5. Call out the split between X11 asynchronous sessions and blocking direct sessions.
6. End honestly with limitations and where the design should harden next.

---

# Closing

`greeter` is small by design.

Its value is not that it replaces every display manager.

Its value is that the whole login path is visible, auditable, and custom enough to fit one machine very well.
