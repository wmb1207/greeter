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
require "./libs"
require "./account"
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
# Moonlight streaming session
# ═══════════════════════════════════════════════════════════════════════════════
#
# Runs moonlight-qt directly on the KMS/DRM framebuffer (SDL_VIDEODRIVER=kmsdrm)
# — no X server needed.  PAM session is still opened so logind registers the
# session and creates /run/user/<uid> (needed for PipeWire audio).

def launch_moonlight(account : Account, pamh : LibPAM::PamHandle, host : String)
  user = account.name
  session_path = Platform.session_path(account.home, user)

  moonlight_cmd = session_path.split(":")
    .flat_map { |d| ["#{d}/moonlight", "#{d}/moonlight-qt"] }
    .find { |p| File::Info.executable?(p) }
  if moonlight_cmd.nil?
    Logger.error("session.moonlight.command_missing", "moonlight command not found in session PATH", {username: user, uid: account.uid, host: host})
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    return
  end
  Logger.debug("session.moonlight.command_resolved", "Resolved moonlight command", {username: user, uid: account.uid, command: moonlight_cmd})

  tty = Platform.current_tty || Platform.tty_path(1)
  LibPAM.pam_set_item(pamh, LibPAM::PAM_TTY, tty.to_unsafe.as(Void*))
  ["XDG_SESSION_TYPE=x11", "XDG_SESSION_CLASS=user",
   "XDG_SEAT=seat0", "XDG_VTNR=1"].each do |kv|
    LibPAM.pam_putenv(pamh, kv)
  end

  ret = Sessions.open_pam_session(pamh)
  if ret != LibPAM::PAM_SUCCESS
    Logger.error("session.moonlight.pam_open_failed", "PAM session could not open", {username: user, uid: account.uid, host: host, pam_code: ret})
    LibPAM.pam_end(pamh, ret)
    return
  end

  pam_env = {} of String => String
  Sessions.env_vars_from_pam(pamh) { |k, v| pam_env[k] = v }

  env = {
    "HOME"             => account.home,
    "USER"             => user,
    "SHELL"            => account.shell,
    "LOGNAME"          => user,
    "PATH"             => session_path,
    "XDG_RUNTIME_DIR"  => Platform.runtime_dir(account.uid),
    "XDG_SESSION_TYPE" => "x11",
    "XDG_SEAT"         => "seat0",
    "XDG_VTNR"         => "1",
    # Tell SDL2 to render directly to the KMS/DRM framebuffer — no X needed.
    "SDL_VIDEODRIVER" => "kmsdrm",
  }
  pam_env.each { |k, v| env[k] ||= v }

  Logger.info("session.moonlight.starting", "Starting Moonlight session", {username: user, uid: account.uid, host: host})

  pid = LibC.fork
  if pid == 0
    Sessions.in_child("session.moonlight.exec_failed") do
      Sessions.prepare_user_child(account, tty)
      Process.exec(command: moonlight_cmd, args: ["stream", host, "Desktop"], env: env, clear_env: true)
    end
  elsif pid < 0
    Logger.error("session.moonlight.fork_failed", "Could not fork Moonlight session", {username: user, uid: account.uid, host: host})
    Sessions.close_pam_session(pamh)
    return
  end

  status = Sessions.wait_child(pid)
  Sessions.close_pam_session(pamh)
  Platform.restore_tty(tty)
  Sessions.log_session_end("moonlight", status, {username: user, uid: account.uid, host: host})
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

class Greeter
  def initialize(@config : Config)
    @keyboard_layout = @config.default_keyboard_layout
    @display_initialized = false
    @first_boot_empty_submit = true
  end

  def run
    loop { do_run }
  end

  private def do_run : Action
    SessionTracker.prune_finished

    keymap_result = Platform.apply_keymap(@keyboard_layout)
    Terminal.prepare_display
    unless @display_initialized
      Terminal.wait_for_stable_size
      @display_initialized = true
    end

    panel_width = draw_login_screen(keymap_result)

    # ── flush stale input before prompting ────────────────────────────────────
    LibC.tcflush(STDIN.fd, LibC::TCIFLUSH)

    if @first_boot_empty_submit
      Terminal.draw_login_prompt(panel_width)
      sleep 1.second
      @first_boot_empty_submit = false
      return Action::NEXT_ITER
    end

    creds_result = Terminal.read_auth_inputs(@keyboard_layout, panel_width)
    return Action::NEXT_ITER unless creds_result.is_ok?

    username, password, @keyboard_layout = creds_result.value.not_nil!
    authenticated_result = Auth.auth(
      Auth::Credentials.new(username: username, password: password),
      Platform.current_tty
    )

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

  private def draw_login_screen(keymap_result : Platform::CommandResult) : Int32
    Terminal.clear_screen
    right_col, rows = Terminal.draw_sidebar
    _, cols = Terminal.term_size
    bar_col = [cols // 5, 4].max
    panel_width = bar_col - 1 # usable columns in the left panel
    Terminal.draw_machine_details(right_col, rows)
    show_keymap_status(keymap_result, panel_width)

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
    panel_width
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
        SessionTracker.prune_finished
        vt = SessionTracker.next_vt
        if vt.nil?
          STDOUT.print "\e[#{choice_row + 1};1H#{Colors::ERROR}All session slots in use (max #{SessionTracker.capacity}).#{Colors::RESET}"
          STDOUT.flush
          sleep 2.seconds
          LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
        else
          result = Sessions.launch_session(
            authenticated.account, authenticated.pamh,
            session.exec,
            vt, @config.seat
          )
          unless result.is_ok?
            Logger.error("session.x11.launch_failed", "X11 session launch failed", {username: authenticated.username, uid: authenticated.account.uid, error: result.error})
            # launch_session already cleaned up pamh on error
          end
        end
      in .wayland?
        result = Sessions.launch_wayland_session(
          authenticated.account, authenticated.pamh,
          session.exec,
          @config.vt, @config.seat
        )
        unless result.is_ok?
          Logger.error("session.wayland.launch_failed", "Wayland session launch failed", {username: authenticated.username, uid: authenticated.account.uid, error: result.error})
        end
      end
    elsif idx >= wm_count && idx < wm_count + config_entries.size
      dispatch_entry(config_entries[idx - wm_count], authenticated, choice_row)
    else
      LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
    end

    Action::NO_ACTION
  end

  private def show_keymap_status(result : Platform::CommandResult, panel_width : Int)
    if result.is_ok?
      Terminal.draw_keyboard_layout(@keyboard_layout, panel_width)
      Logger.info("keyboard.layout_changed", "Keyboard layout changed", {layout: @keyboard_layout.keymap})
    else
      Logger.warn("keyboard.layout_change_failed", "Keyboard layout change failed", {layout: @keyboard_layout.keymap, error: result.error})
      msg = "layout failed: #{@keyboard_layout.label}"
      STDOUT.print "\e[8;1H#{Colors::ERROR}#{msg[0, panel_width].ljust(panel_width)}#{Colors::RESET}"
      STDOUT.flush
    end
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
        session = Sessions.launch_ssh(authenticated.account, authenticated.pamh, host)
        unless session.is_ok?
          Logger.error("session.ssh.launch_failed", "SSH session launch failed", {username: authenticated.username, uid: authenticated.account.uid, host: host, error: session.error})
          LibPAM.pam_end(authenticated.pamh, LibPAM::PAM_SUCCESS)
        end
      end
    in .moonlight?
      launch_moonlight(authenticated.account, authenticated.pamh, entry.host || "localhost")
    end
  end
end

def main
  config = Config.load
  greeter = Greeter.new(config)
  greeter.run
end

main
