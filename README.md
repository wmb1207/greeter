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

| Choice | Action |
|--------|--------|
| 1 | fvwm3 via startx (X11) |
| 2 | Exit greeter |
| 3 | Reboot |
| 4 | Shutdown |
| 5 | SSH to `desktop.wmb.arpa` |
| 6 | Moonlight stream from `desktop.wmb.arpa` (KMS/DRM, no X needed) |

## Architecture

```
src/
  greeter.cr    # Main loop, Greeter class, session menu
  auth.cr       # PAM authentication, LoginSession
  sessions.cr   # X session + SSH session launch
  terminal.cr   # TTY input/output, sidebar, credential prompts
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
