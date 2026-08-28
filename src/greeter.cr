2 # crystal-greeter: minimal TTY-based login greeter for Linux
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
require "./sessions"
require "./session_tracker"
require "./action"
require "./config"
require "./logger"
require "./platform"
require "./keyboard_layout"

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
    Logger.error("privileges.initgroups_failed", "Could not initialize supplementary groups", {uid: pw.pw_uid})
    return false
  end
  if LibC.setgid(pw.pw_gid) != 0
    Logger.error("privileges.setgid_failed", "Could not set process gid", {uid: pw.pw_uid, gid: pw.pw_gid})
    return false
  end
  if LibC.setuid(pw.pw_uid) != 0
    Logger.error("privileges.setuid_failed", "Could not set process uid", {uid: pw.pw_uid})
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

# ═══════════════════════════════════════════════════════════════════════════════
# Moonlight streaming session
# ═══════════════════════════════════════════════════════════════════════════════
#
# Runs moonlight-qt directly on the KMS/DRM framebuffer (SDL_VIDEODRIVER=kmsdrm)
# — no X server needed.  PAM session is still opened so logind registers the
# session and creates /run/user/<uid> (needed for PipeWire audio).

def launch_moonlight(pw : LibC::Passwd, pamh : LibPAM::PamHandle, host : String)
  user = String.new(pw.pw_name)
  home = String.new(pw.pw_dir)
  shell = String.new(pw.pw_shell)

  session_path = Platform.session_path(home, user)

  moonlight_cmd = session_path.split(":")
    .flat_map { |d| ["#{d}/moonlight", "#{d}/moonlight-qt"] }
    .find { |p| File::Info.executable?(p) }
  if moonlight_cmd.nil?
    Logger.error("session.moonlight.command_missing", "moonlight command not found in session PATH", {username: user, uid: pw.pw_uid, host: host})
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    return
  end
  Logger.debug("session.moonlight.command_resolved", "Resolved moonlight command", {username: user, uid: pw.pw_uid, command: moonlight_cmd})

  tty_path_str = LibC.ttyname(STDIN.fd)
  tty_str = tty_path_str.null? ? Platform.tty_path(1) : String.new(tty_path_str)
  tty_str.to_unsafe.as(Void*).tap do |ptr|
    LibPAM.pam_set_item(pamh, LibPAM::PAM_TTY, ptr)
  end
  ["XDG_SESSION_TYPE=x11", "XDG_SESSION_CLASS=user",
   "XDG_SEAT=seat0", "XDG_VTNR=1"].each do |kv|
    LibPAM.pam_putenv(pamh, kv)
  end

  ret = LibPAM.pam_open_session(pamh, 0)
  if ret != LibPAM::PAM_SUCCESS
    Logger.error("session.moonlight.pam_open_failed", "PAM session could not open", {username: user, uid: pw.pw_uid, host: host, pam_code: ret})
  end

  pam_env = {} of String => String
  envlist = LibPAM.pam_getenvlist(pamh)
  unless envlist.null?
    i = 0
    while !(ptr = envlist[i]).null?
      pair = String.new(ptr)
      eq = pair.index('=')
      pam_env[pair[0...eq]] = pair[(eq + 1)..] if eq
      i += 1
    end
  end

  env = {
    "HOME"             => home,
    "USER"             => user,
    "SHELL"            => shell,
    "LOGNAME"          => user,
    "PATH"             => session_path,
    "XDG_RUNTIME_DIR"  => Platform.runtime_dir(pw.pw_uid),
    "XDG_SESSION_TYPE" => "x11",
    "XDG_SEAT"         => "seat0",
    "XDG_VTNR"         => "1",
    # Tell SDL2 to render directly to the KMS/DRM framebuffer — no X needed.
    "SDL_VIDEODRIVER" => "kmsdrm",
  }
  pam_env.each { |k, v| env[k] ||= v }

  Logger.info("session.moonlight.starting", "Starting Moonlight session", {username: user, uid: pw.pw_uid, host: host})
  puts "Connecting to #{host} via Moonlight..."

  pid = LibC.fork
  if pid == 0
    tty_path = LibC.ttyname(STDIN.fd)
    unless tty_path.null?
      LibC.chown(tty_path, pw.pw_uid, pw.pw_gid)
    end

    unless drop_privileges(pw)
      Logger.error("session.moonlight.privilege_drop_failed", "Privilege drop failed; Moonlight session aborted", {username: user, uid: pw.pw_uid, host: host})
      exit 1
    end
    Dir.cd(home)

    begin
      Process.exec(
        command: moonlight_cmd,
        args: ["stream", host, "Desktop"],
        env: env,
        clear_env: true
      )
    rescue ex
      Logger.error("session.moonlight.exec_failed", "Could not exec moonlight", {username: user, uid: pw.pw_uid, host: host, error: ex.message})
      exit 1
    end
  elsif pid < 0
    Logger.error("session.moonlight.fork_failed", "Could not fork Moonlight session", {username: user, uid: pw.pw_uid, host: host})
    LibPAM.pam_close_session(pamh, 0)
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    return
  end

  raw_status = 0_i32
  LibC.waitpid(pid, pointerof(raw_status), 0)
  exited = (raw_status & 0x7f) == 0
  exit_code = (raw_status >> 8) & 0xff
  if exited && exit_code == 0
    Logger.info("session.moonlight.ended", "Moonlight session ended", {username: user, uid: pw.pw_uid, host: host, exit_code: exit_code})
    puts "Moonlight session ended normally."
  else
    Logger.warn("session.moonlight.ended", "Moonlight session exited abnormally", {username: user, uid: pw.pw_uid, host: host, exit_code: exit_code})
    puts "Moonlight session exited (code #{exit_code})."
  end

  LibPAM.pam_close_session(pamh, 0)
  LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
end

# ═══════════════════════════════════════════════════════════════════════════════
# Stub menu actions (bonus)
# ═══════════════════════════════════════════════════════════════════════════════

def do_reboot
  command, args = Platform.reboot_command
  Process.exec(command, args)
end

def do_shutdown
  command, args = Platform.shutdown_command
  Process.exec(command, args)
end

# ═══════════════════════════════════════════════════════════════════════════════
# Main greeter loop
# ═══════════════════════════════════════════════════════════════════════════════
#
# Ctrl+C returns to the login prompt instead of terminating the process.
# The terminal is never left in a broken state; other TTYs remain accessible
# for recovery in all error paths.

Signal::INT.trap { STDOUT.print "\e[8;1H[^C — back to login]\e[9;1H"; STDOUT.flush }

Signal::CHLD.trap { SessionTracker.request_reap }

def reap_finished_x11_sessions
  return unless SessionTracker.reap_requested? || SessionTracker.size > 0

  SessionTracker.reap_all.each do |reaped|
    entry = reaped.entry
    status = reaped.status
    exited = (status & 0x7f) == 0
    exit_code = (status >> 8) & 0xff
    signal = status & 0x7f

    if exited && exit_code == 0
      Logger.info("session.x11.ended", "X11 session ended", {
        username: entry.username, vt: entry.vt, display: entry.display,
        pid: reaped.pid, exit_code: exit_code,
      })
    elsif exited
      Logger.warn("session.x11.ended", "X11 session exited abnormally", {
        username: entry.username, vt: entry.vt, display: entry.display,
        pid: reaped.pid, exit_code: exit_code,
      })
    else
      Logger.warn("session.x11.ended", "X11 session terminated by signal", {
        username: entry.username, vt: entry.vt, display: entry.display,
        pid: reaped.pid, signal: signal,
      })
    end
  end
end

class Greeter
  def initialize(@config : Config)
    @keyboard_layout = @config.default_keyboard_layout
  end

  def run
    loop { do_run }
  end

  private def do_run : Action
    reap_finished_x11_sessions

    Terminal.clear_screen
    _, rows = Terminal.draw_sidebar
    _, cols = Terminal.term_size
    bar_col = [cols // 5, 4].max
    panel_width = bar_col - 1 # usable columns in the left panel
    Terminal.apply_keymap_feedback(@keyboard_layout, panel_width)

    # ── header box (scales to panel width) ────────────────────────────────────
    inner = [panel_width - 2, 1].max
    title = @config.title
    title = title[0, inner] if title.size > inner
    pad = inner - title.size
    lpad = pad // 2
    rpad = pad - lpad
    STDOUT.print "\e[1;1H#{Colors::BORDER}#{"+" + "-" * inner + "+"}#{Colors::RESET}"
    STDOUT.print "\e[2;1H#{Colors::BORDER}|#{Colors::RESET}#{" " * lpad}#{Colors::TITLE}#{title}#{Colors::RESET}#{" " * rpad}#{Colors::BORDER}|#{Colors::RESET}"
    STDOUT.print "\e[3;1H#{Colors::BORDER}#{"+" + "-" * inner + "+"}#{Colors::RESET}"
    STDOUT.flush

    # ── flush stale input before prompting ────────────────────────────────────
    LibC.tcflush(STDIN.fd, LibC::TCIFLUSH)

    Terminal.draw_keyboard_layout(@keyboard_layout, panel_width)
    creds_result = Terminal.read_auth_inputs(@keyboard_layout, panel_width)
    return Action::NEXT_ITER unless creds_result.is_ok?

    username, password, @keyboard_layout = creds_result.value.not_nil!
    authenticated_result = Auth.auth(Auth::Credentials.new(
      username: username,
      password: password
    ))

    if !authenticated_result.is_ok?
      msg = authenticated_result.error.not_nil!
      STDOUT.print "\e[8;1H#{Colors::ERROR}#{msg[0, panel_width].ljust(panel_width)}#{Colors::RESET}"
      STDOUT.flush
      sleep 2.seconds
      return Action::NEXT_ITER
    end

    authenticated = authenticated_result.value.not_nil!

    welcome = "Hi, #{authenticated.username}."
    STDOUT.print "\e[8;1H#{Colors::SUCCESS}#{welcome[0, panel_width].ljust(panel_width)}#{Colors::RESET}"
    STDOUT.flush

    menu panel_width, authenticated
  end

  private def menu(panel_width : Int, authenticated : Auth::LoginSession)
    # ── session menu ──────────────────────────────────────────────────────────
    wm_sessions = Sessions.available_sessions(@config.xsession_dirs, @config.wayland_session_dirs)
    config_entries = @config.menu

    all_labels = wm_sessions.map(&.label) + config_entries.map(&.label)
    all_labels.each_with_index do |label, i|
      num = "#{Colors::NUMBER}#{i + 1})#{Colors::RESET}"
      lbl = "#{Colors::ITEM}#{label}#{Colors::RESET}"
      plain = "#{i + 1}) #{label}"
      pad = " " * [panel_width - plain.size, 0].max
      STDOUT.print "\e[#{10 + i};1H#{num} #{lbl}#{pad}"
    end

    default = wm_sessions.empty? ? "" : "1"
    choice_row = 10 + all_labels.size + 1
    STDOUT.print "\e[#{choice_row};1H#{Colors::MUTED}Choice [#{default}]:#{Colors::RESET} "
    STDOUT.flush

    choice = (STDIN.gets(chomp: true) || "").strip
    choice = default if choice.empty?
    idx = (choice.to_i? || 0) - 1
    wm_count = wm_sessions.size

    if idx >= 0 && idx < wm_count
      session = wm_sessions[idx]
      case session.session_type
      in .x11?
        reap_finished_x11_sessions
        vt = SessionTracker.next_vt
        if vt.nil?
          STDOUT.print "\e[#{choice_row + 1};1H#{Colors::ERROR}All session slots in use (max #{SessionTracker.capacity}).#{Colors::RESET}"
          STDOUT.flush
          sleep 2.seconds
          LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
        else
          result = Sessions.launch_session(
            authenticated.pw, authenticated.pamh,
            session.exec,
            vt, @config.seat
          )
          unless result.is_ok?
            Logger.error("session.x11.launch_failed", "X11 session launch failed", {username: authenticated.username, uid: authenticated.pw.pw_uid, error: result.error})
            # launch_session already cleaned up pamh on error
          end
        end
      in .wayland?
        result = Sessions.launch_wayland_session(
          authenticated.pw, authenticated.pamh,
          session.exec,
          @config.vt, @config.seat
        )
        unless result.is_ok?
          Logger.error("session.wayland.launch_failed", "Wayland session launch failed", {username: authenticated.username, uid: authenticated.pw.pw_uid, error: result.error})
        end
      end
    elsif idx >= wm_count && idx < wm_count + config_entries.size
      dispatch_entry(config_entries[idx - wm_count], authenticated, choice_row)
    else
      LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
    end

    Action::NO_ACTION
  end

  private def dispatch_entry(entry : MenuEntry, authenticated : Auth::LoginSession, choice_row : Int)
    case entry.action
    in .exit?
      LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
      STDOUT.print "\e[#{choice_row + 1};1H#{Colors::MUTED}Goodbye.#{Colors::RESET}"
      STDOUT.flush
      exit 0
    in .reboot?
      LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
      do_reboot
    in .shutdown?
      LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
      do_shutdown
    in .ssh?
      STDOUT.print "\e[#{choice_row + 1};1H#{Colors::PROMPT}Host:#{Colors::RESET} "
      STDOUT.flush
      host = (STDIN.gets(chomp: true) || "").strip
      if host.empty?
        LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
      else
        session = Sessions.launch_ssh(authenticated.pw, authenticated.pamh, host)
        unless session.is_ok?
          Logger.error("session.ssh.launch_failed", "SSH session launch failed", {username: authenticated.username, uid: authenticated.pw.pw_uid, host: host, error: session.error})
          LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
        end
      end
    in .moonlight?
      launch_moonlight(authenticated.pw, authenticated.pamh, entry.host || "localhost")
    end
  end
end

def main
  config = Config.load
  greeter = Greeter.new(config)
  greeter.run
end

main
