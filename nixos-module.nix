{ config, lib, pkgs, ... }:

let
  cfg = config.services.crystal-greeter;
  fmt = pkgs.formats.yaml { };

  # Build the config attrset, dropping null fields from each menu entry
  # so the Crystal parser sees absent keys rather than YAML nulls.
  configAttrs = {
    title         = cfg.title;
    vt            = cfg.vt;
    seat          = cfg.seat;
    xsession_dirs = cfg.xsessionDirs;
    wayland_session_dirs = cfg.waylandSessionDirs;
    menu          = map
      (e: lib.filterAttrs (_: v: v != null) {
        action = e.action;
        label  = e.label;
        host   = e.host;
      })
      cfg.menu;
  };

  configFile = fmt.generate "greeter.conf" configAttrs;
in
{
  # ── options ──────────────────────────────────────────────────────────────────

  options.services.crystal-greeter = {

    enable = lib.mkEnableOption "crystal-greeter TTY login greeter";

    package = lib.mkOption {
      type        = lib.types.package;
      description = "The crystal-greeter package to use.";
    };

    title = lib.mkOption {
      type        = lib.types.str;
      default     = "Greeter";
      description = "Title shown in the header box.";
    };

    vt = lib.mkOption {
      type        = lib.types.ints.positive;
      default     = 1;
      description = "Virtual terminal number the greeter runs on.";
    };

    seat = lib.mkOption {
      type        = lib.types.str;
      default     = "seat0";
      description = "Seat identifier passed to logind.";
    };

    xsessionDirs = lib.mkOption {
      type        = lib.types.listOf lib.types.str;
      default     = [
        "/run/current-system/sw/share/xsessions"
        "/usr/share/xsessions"
      ];
      description = "Directories scanned for .desktop X session files.";
    };

    waylandSessionDirs = lib.mkOption {
      type        = lib.types.listOf lib.types.str;
      default     = [
        "/run/current-system/sw/share/wayland-sessions"
        "/usr/share/wayland-sessions"
      ];
      description = "Directories scanned for .desktop Wayland session files.";
    };

    menu = lib.mkOption {
      description = "Static menu entries shown after discovered X sessions.";
      default = [
        { action = "exit";     label = null; host = null; }
        { action = "reboot";   label = null; host = null; }
        { action = "shutdown"; label = null; host = null; }
        { action = "ssh";      label = null; host = null; }
      ];
      type = lib.types.listOf (lib.types.submodule {
        options = {
          action = lib.mkOption {
            type        = lib.types.enum [ "exit" "reboot" "shutdown" "ssh" "moonlight" ];
            description = "Action to perform when this entry is selected.";
          };
          label = lib.mkOption {
            type        = lib.types.nullOr lib.types.str;
            default     = null;
            description = "Display label. Derived from action+host if null.";
          };
          host = lib.mkOption {
            type        = lib.types.nullOr lib.types.str;
            default     = null;
            description = "Target host for ssh and moonlight actions.";
          };
        };
      });
    };
  };

  # ── implementation ────────────────────────────────────────────────────────────

  config = lib.mkIf cfg.enable {

    # Place the generated config at /etc/greeter.conf
    environment.etc."greeter.conf".source = configFile;

    # Make sure xsession .desktop files from installed WMs are linked
    # into /run/current-system/sw/share/xsessions/
    environment.pathsToLink = [ "/share/xsessions" "/share/wayland-sessions" ];

    # Install as a setuid-root wrapper (required for PAM + privilege drop)
    security.wrappers.crystal-greeter = {
      source = "${cfg.package}/bin/crystal-greeter";
      owner  = "root";
      group  = "root";
      setuid = true;
    };

    # Disable the normal getty on the chosen VT
    systemd.services."getty@tty${toString cfg.vt}".enable  = false;
    systemd.services."autovt@tty${toString cfg.vt}".enable = false;

    systemd.services.crystal-greeter = {
      description = "Crystal TTY greeter";
      after       = [ "systemd-user-sessions.service" ];
      wantedBy    = [ "multi-user.target" ];
      conflicts   = [ "getty@tty${toString cfg.vt}.service" ];
      serviceConfig = {
        # Silence kernel console messages on ttyN before the greeter draws.
        # Without this, kernel printk output (module init, udev, etc.) gets
        # written directly to the framebuffer on top of the greeter UI.
        # Level 1 = KERN_EMERG only; messages still accumulate in the ring
        # buffer and are readable via dmesg / journalctl -k.
        ExecStartPre   = "${pkgs.util-linux}/bin/dmesg -n 1";
        ExecStart      = "/run/wrappers/bin/crystal-greeter";
        StandardInput  = "tty";
        StandardOutput = "tty";
        StandardError  = "journal";
        TTYPath        = "/dev/tty${toString cfg.vt}";
        TTYReset       = true;
        TTYVHangup     = true;
        Restart        = "always";
        RestartSec     = "1s";
      };
    };
  };
}
