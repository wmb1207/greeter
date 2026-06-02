# crystal-greeter

A minimal TTY-based login greeter for Linux, written in Crystal.

## What it does

Runs on a bare TTY (tty1) and handles the full login flow:

1. Prompt for username and password (password input is hidden)
2. Authenticate via PAM
3. Present a session menu
4. Fork, drop privileges, and exec the chosen session
5. Wait for the session to exit, then loop back to the login prompt

Because it uses `fork()` + privilege drop, the greeter process itself stays
root throughout — only the child drops to the user's UID/GID before exec.

## Session menu

The menu is config-driven (see [Configuration](#configuration) below).
X sessions are discovered automatically from `.desktop` files.
Static entries follow — by default:

| Entry | Action |
|-------|--------|
| (discovered xsessions) | X11 session via startx |
| exit | Exit greeter |
| reboot | `systemctl reboot` |
| shutdown | `systemctl poweroff` |
| ssh | SSH to a host (prompted) |
| moonlight | Moonlight stream via KMS/DRM (no X needed) |

## Configuration

The greeter reads `/etc/greeter.conf` on startup (YAML). All fields are
optional — missing keys fall back to compiled-in defaults.

```yaml
title: "WMB Greeter"
vt: 1        # virtual terminal number
seat: seat0

xsession_dirs:
  - /run/current-system/sw/share/xsessions
  - /usr/share/xsessions

menu:
  - action: exit
  - action: reboot
  - action: shutdown
  - action: ssh
  - action: moonlight
    host: desktop.wmb.arpa
    label: "moonlight desktop.wmb.arpa"  # optional, derived if omitted
```

Supported actions: `exit`, `reboot`, `shutdown`, `ssh`, `moonlight`.
If the file is absent or unparseable, defaults are used and a warning is
printed to stderr.

## Architecture

```
src/
  greeter.cr    # Main loop, Greeter class, session menu, action dispatch
  config.cr     # Config struct, MenuAction enum, YAML loading
  logger.cr     # JSONL operational logging
  auth.cr       # PAM authentication, LoginSession
  sessions.cr   # X session + SSH session launch
  terminal.cr   # TTY input/output, sidebar, credential prompts, Colors
  libs.cr       # LibC + LibPAM bindings
  action.cr     # Action enum (flow control)
  result.cr     # Generic Result(T) type
```

## Requirements

- Linux with PAM (`linux-pam`)
- NixOS (uses nix store paths for `coreutils`, `util-linux`, `xinit`)
- `startx` + `fvwm3` for X sessions
- `systemd` (session registered via `systemd-run --user --scope`)

## Build

Requires the nix dev shell for `linux-pam` headers:

```sh
nix develop --command make build   # release build
make debug                         # debug build (faster compile)
make spec                          # logger specs
```

## Logging

Operational diagnostics are emitted as JSONL on stderr. The NixOS service sends
stderr to journald while keeping the interactive UI on the TTY. Each record has
`timestamp`, `level`, `event`, `message`, and nested `fields` keys.

```sh
journalctl -u crystal-greeter.service -o cat
```

## Install

```sh
make install
```

Installs to `/usr/local/bin/crystal-greeter` with the **setuid-root** bit set.
This is required so the greeter can call PAM, `initgroups`, `setgid`, and `setuid`.

## Why Crystal?

Compiled to a single native binary with no runtime dependencies, strong static
typing, and Ruby-like syntax — a good fit for a small systems tool that needs
to be correct and fast.
