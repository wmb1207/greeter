# crystal-greeter: minimal TTY-based login greeter for Linux
#
# Flow:  prompt username → prompt password (hidden) → PAM auth →
#        session menu → fork+exec startx/fvwm3 → wait → repeat
#
# Needs to run as root (or setuid-root) so it can call PAM,
# initgroups, setgid, and setuid.
#
# Build:   make build
# Install: make install   (sets setuid bit)

require "signal"
# require "io/console"   # pulls in LibC::Termios, ECHO, TCSANOW, tcgetattr, tcsetattr
require "./libs"
require "./auth"
require "./terminal"

# ═══════════════════════════════════════════════════════════════════════════════
# User lookup
# ═══════════════════════════════════════════════════════════════════════════════

def find_user(username : String) : LibC::Passwd?
  ptr = LibC.getpwnam(username)
  ptr.null? ? nil : ptr.value
end

# ═══════════════════════════════════════════════════════════════════════════════
# Privilege dropping
# ═══════════════════════════════════════════════════════════════════════════════
#
# Order is mandatory: initgroups → setgid → setuid.
# setuid must come last: once a process drops to an unprivileged UID it can
# no longer alter its GID or supplementary groups on Linux.

def drop_privileges(pw : LibC::Passwd) : Bool
  if LibC.initgroups(pw.pw_name, pw.pw_gid) != 0
    STDERR.puts "greeter: initgroups failed"
    return false
  end
  if LibC.setgid(pw.pw_gid) != 0
    STDERR.puts "greeter: setgid(#{pw.pw_gid}) failed"
    return false
  end
  if LibC.setuid(pw.pw_uid) != 0
    STDERR.puts "greeter: setuid(#{pw.pw_uid}) failed"
    return false
  end
  true
end

# ═══════════════════════════════════════════════════════════════════════════════
# Session launch
# ═══════════════════════════════════════════════════════════════════════════════
#
# We fork() so the child can drop privileges without touching the greeter
# process.  startx is exec'd as an array of arguments — no shell is involved,
# so there is no possibility of command injection regardless of the username
# or home directory values.
#
# The parent blocks in child.wait until the X session terminates, then
# returns to the greeter loop.

def launch_session(pw : LibC::Passwd, pamh : LibPAM::PamHandle)
  user  = String.new(pw.pw_name)
  home  = String.new(pw.pw_dir)
  shell = String.new(pw.pw_shell)

  # Build a PATH for the child session.
  # On NixOS, tools like uname/expr/hexdump may only exist in nix store paths
  # not exposed via /run/current-system/sw/bin.  Find coreutils and util-linux
  # directly in /nix/store so startx can locate them regardless of profile state.
  nix_extra = [] of String
  ["coreutils", "util-linux", "xinit"].each do |pkg|
    Dir.glob("/nix/store/*-#{pkg}-*/bin").each { |d| nix_extra << d }
  end

  base_dirs = [
    "#{home}/.local/bin",
    "#{home}/.nix-profile/bin",
    "/nix/var/nix/profiles/per-user/#{user}/bin",
    "/run/current-system/sw/bin",
    "/nix/var/nix/profiles/default/bin",
    "/run/wrappers/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
  ]
  greeter_path = (ENV["PATH"]? || "").split(":").reject(&.empty?)
  session_path = (greeter_path + nix_extra + base_dirs).uniq.join(":")

  # Resolve startx to an absolute path by searching session_path directly.
  # Process.find_executable uses the greeter's live PATH (minimal on a TTY/init),
  # so we search the extended session_path we built above instead.
  startx_cmd = session_path.split(":")
               .map { |d| "#{d}/startx" }
               .find { |p| File::Info.executable?(p) }
  if startx_cmd.nil?
    STDERR.puts "greeter: startx not found in session PATH: #{session_path}"
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    return
  end
  STDERR.puts "greeter: startx resolved to #{startx_cmd}"

  # Tell pam_systemd which TTY and seat/VT this session belongs to.
  # These must be set BEFORE pam_open_session so logind registers the
  # session as Active=yes on seat0/vt1.  Without this polkit refuses
  # reboot/shutdown with "interactive authentication required".
  tty_path_str = LibC.ttyname(STDIN.fd)
  tty_str = tty_path_str.null? ? "/dev/tty1" : String.new(tty_path_str)
  tty_str.to_unsafe.as(Void*).tap do |ptr|
    LibPAM.pam_set_item(pamh, LibPAM::PAM_TTY, ptr)
  end
  ["XDG_SESSION_TYPE=x11", "XDG_SESSION_CLASS=user",
   "XDG_SEAT=seat0", "XDG_VTNR=1"].each do |kv|
    LibPAM.pam_putenv(pamh, kv)
  end

  # Register the session with systemd-logind.  This creates /run/user/<uid>,
  # starts the user's systemd slice (and with it PipeWire/PulseAudio), and
  # sets up the PAM environment for the session.  Without this call there is
  # no audio because the audio server never starts.
  ret = LibPAM.pam_open_session(pamh, 0)
  if ret != LibPAM::PAM_SUCCESS
    STDERR.puts "greeter: pam_open_session failed (#{ret}) — audio may be unavailable"
  end

  # Collect environment variables written by PAM modules (pam_systemd in
  # particular sets XDG_SESSION_ID and DBUS_SESSION_BUS_ADDRESS which are
  # required for PipeWire / D-Bus to work in the session).
  pam_env = {} of String => String
  envlist = LibPAM.pam_getenvlist(pamh)
  unless envlist.null?
    i = 0
    while !(ptr = envlist[i]).null?
      pair = String.new(ptr)
      eq   = pair.index('=')
      pam_env[pair[0...eq]] = pair[(eq + 1)..] if eq
      i += 1
    end
  end

  # Minimal, clean environment for the X session.
  # clear_env: true ensures no root-owned variables leak into the session.
  # ENV tells ksh/loksh which rc file to source for interactive subshells
  # (terminal emulators inside the X session).
  env = {
    "HOME"              => home,
    "USER"              => user,
    "SHELL"             => shell,
    "LOGNAME"           => user,
    "PATH"              => session_path,
    "ENV"               => "#{home}/.kshrc",
    # Required by PipeWire / PulseAudio to locate their socket.
    # pam_open_session (via pam_systemd) creates this directory;
    # we set it explicitly so the child always has the right value.
    "XDG_RUNTIME_DIR"   => "/run/user/#{pw.pw_uid}",
    # Tells systemd-logind / D-Bus what kind of session this is.
    "XDG_SESSION_TYPE"  => "x11",
    "XDG_SESSION_CLASS" => "user",
    "XDG_SEAT"          => "seat0",
    "XDG_VTNR"          => "1",
  }

  # Merge PAM-supplied variables (e.g. XDG_SESSION_ID, DBUS_SESSION_BUS_ADDRESS
  # from pam_systemd) without overwriting the values we set explicitly above.
  pam_env.each { |k, v| env[k] ||= v }

  puts "Starting fvwm3 session for #{user}..."

  pid = LibC.fork
  if pid == 0
    # ── child ──────────────────────────────────────────────────────────────
    # Give the user ownership of the current TTY before dropping privileges.
    # Xorg needs to open the virtual console (e.g. /dev/tty1) as the session
    # user; without this chown it gets EACCES ("permission denied cannot open
    # virtual console 1").  We still have root here, so the chown succeeds.
    tty_path = LibC.ttyname(STDIN.fd)
    unless tty_path.null?
      LibC.chown(tty_path, pw.pw_uid, pw.pw_gid)
    end

    unless drop_privileges(pw)
      STDERR.puts "greeter: privilege drop failed; session aborted"
      exit 1
    end

    # Change into the user's home directory so $PWD matches $HOME.
    # Without this the process inherits the greeter's cwd (typically /)
    # which breaks anything that relies on a sane working directory.
    Dir.cd(home)

    # Run the X session inside a systemd user scope so that logind tracks
    # the session cgroup and cleans up all child processes when X exits.
    # The login shell sources ~/.profile first (giving us the full HM PATH),
    # then exec's systemd-run which creates the scope and execs startx.
    # --scope   : transient scope unit (systemd-run stays in the PID chain
    #             so the parent's wait() still works correctly)
    # --collect : auto-remove the unit after it exits
    # Using `exec "$@"` with positional args avoids shell-injection risk.
    begin
      Process.exec(
        command:   shell,
        args:      ["-l", "-c", "exec \"$@\"", "--",
                   "systemd-run", "--user", "--scope", "--collect",
                   "--", startx_cmd, "fvwm3", "--", ":0", "vt1"],
        env:       env,
        clear_env: true
      )
    rescue ex
      STDERR.puts "greeter: exec failed: #{ex.message}"
      exit 1
    end
  elsif pid < 0
    STDERR.puts "greeter: fork failed"
    LibPAM.pam_close_session(pamh, 0)
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    return
  end

  # ── parent — wait for the X session to exit ─────────────────────────────
  raw_status = 0_i32
  LibC.waitpid(pid, pointerof(raw_status), 0)
  exited    = (raw_status & 0x7f) == 0
  exit_code = (raw_status >> 8) & 0xff
  if exited && exit_code == 0
    puts "Session ended normally."
  else
    puts "Session exited (code #{exit_code})."
  end

  # Close the PAM session (tears down the systemd-logind session, stops user
  # services) then end the transaction.
  LibPAM.pam_close_session(pamh, 0)
  LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
end

# ═══════════════════════════════════════════════════════════════════════════════
# Stub menu actions (bonus)
# ═══════════════════════════════════════════════════════════════════════════════

def do_reboot
  puts "  [stub] reboot — would exec: systemctl reboot"
end

def do_shutdown
  puts "  [stub] shutdown — would exec: systemctl poweroff"
end

# ═══════════════════════════════════════════════════════════════════════════════
# Main greeter loop
# ═══════════════════════════════════════════════════════════════════════════════
#
# Ctrl+C returns to the login prompt instead of terminating the process.
# The terminal is never left in a broken state; other TTYs remain accessible
# for recovery in all error paths.

Signal::INT.trap { STDOUT.print "\e[8;1H[^C — back to login]\e[9;1H"; STDOUT.flush }

enum Action : UInt8
  NO_ACTION = 0
  NEXT_ITER = 1
end

class Greeter

  def run
    loop do
      do_run
      # case do_run
      # when Action::NEXT_ITER
      #   next
      # end
    end
  end

  private def do_run : Action
    Terminal.clear_screen
    _, rows = Terminal.draw_sidebar
    _, cols = Terminal.term_size
    bar_col     = [cols // 5, 4].max
    panel_width = bar_col - 1   # usable columns in the left panel

    # ── header box (scales to panel width) ────────────────────────────────────
    inner = [panel_width - 2, 1].max
    title = "WMB Greeter"
    title = title[0, inner] if title.size > inner
    pad   = inner - title.size
    lpad  = pad // 2
    rpad  = pad - lpad
    STDOUT.print "\e[1;1H#{"+" + "-" * inner + "+"}"
    STDOUT.print "\e[2;1H#{"|" + " " * lpad + title + " " * rpad + "|"}"
    STDOUT.print "\e[3;1H#{"+" + "-" * inner + "+"}"
    STDOUT.flush

  # ── flush stale input before prompting ────────────────────────────────────
    LibC.tcflush(STDIN.fd, LibC::TCIFLUSH)

    creds_result = Terminal.read_auth_inputs
    return Action::NEXT_ITER unless creds_result.is_ok?

    username, password = creds_result.value.not_nil!
    authenticated_result = Auth.auth(Auth::Credentials.new(
                                      username: username,
                                      password: password
                                    ))

    if !authenticated_result.is_ok?
      msg = authenticated_result.error.not_nil!
      STDOUT.print "\e[8;1H#{msg[0, panel_width].ljust(panel_width)}"
      STDOUT.flush
      sleep 2.seconds
      return Action::NEXT_ITER
    end

    authenticated = authenticated_result.value.not_nil!

    welcome = "Hi, #{authenticated.username}."
    STDOUT.print "\e[8;1H#{welcome[0, panel_width].ljust(panel_width)}"
    STDOUT.flush

    menu panel_width, authenticated
  end

  private def menu(panel_width : Int , authenticated : Auth::LoginSession)
    # ── session menu ──────────────────────────────────────────────────────────
    menu = [
      "1) fvwm3",
      "2) exit",
      "3) reboot",
      "4) shutdown",
    ]
    menu.each_with_index do |line, i|
      STDOUT.print "\e[#{10 + i};1H#{line[0, panel_width].ljust(panel_width)}"
    end
    choice_row = 10 + menu.size + 1
    STDOUT.print "\e[#{choice_row};1HChoice [1]: "
    STDOUT.flush
    
    choice = (STDIN.gets(chomp: true) || "").strip
    choice = "1" if choice.empty?
    
    case choice
    when "1"
      launch_session(authenticated.pw, authenticated.pamh)   # owns pamh; calls pam_close_session + pam_end
    when "2"
      LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
      STDOUT.print "\e[#{choice_row + 1};1HGoodbye."
      STDOUT.flush
      exit 0
    when "3"
      LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
      do_reboot
    when "4"
      LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
      do_shutdown
    else
      LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
    end

    Action::NO_ACTION
  end
end

def main
  greeter = Greeter.new
  greeter.run
end

main
