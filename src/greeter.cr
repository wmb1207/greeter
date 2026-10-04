# crystal-greeter: minimal TTY-based login greeter for Linux
#
# Flow:  prompt username → prompt password (hidden) → PAM auth →
#        session menu → Supervisor runs the session → repeat
#
# Needs to run as root (or setuid-root) so it can call PAM,
# initgroups, setgid, and setuid.
#
# Build:   make build
# Install: make install   (sets setuid bit)

require "./auth"
require "./config"
require "./keyboard_layout"
require "./libs"
require "./logger"
require "./platform"
require "./session_tracker"
require "./sessions"
require "./supervisor"
require "./terminal"

# Ctrl+C must not terminate the greeter.  The handler only acknowledges the
# keypress; whatever is being typed stays on screen.
Signal::INT.trap { STDOUT.print "\e[8;1H[^C]\e[9;1H"; STDOUT.flush }

class Greeter
  MESSAGE_ROW =  8
  MENU_ROW    = 10

  def initialize(@config : Config)
    @keyboard_layout = @config.default_keyboard_layout
    @display_initialized = false
    # The first pass only draws the screen and pauses before reading input,
    # so keystrokes buffered while the console was still settling at boot
    # are discarded instead of being submitted.
    @first_pass = true
  end

  def run : NoReturn
    loop { run_once }
  end

  private def run_once : Nil
    SessionTracker.prune_finished

    keymap_failure = Platform.apply_keymap(@keyboard_layout)
    Terminal.prepare_display
    unless @display_initialized
      Terminal.wait_for_stable_size
      @display_initialized = true
    end

    panel_width = draw_login_screen(keymap_failure)

    # ── flush stale input before prompting ────────────────────────────────────
    LibC.tcflush(STDIN.fd, LibC::TCIFLUSH)

    if @first_pass
      Terminal.draw_login_prompt(panel_width)
      sleep 1.second
      @first_pass = false
      return
    end

    input = Terminal.read_auth_inputs(@keyboard_layout, panel_width)
    return if input.is_a?(Failure)

    @keyboard_layout = input.layout
    credentials = Auth::Credentials.new(input.username, input.password)
    failure = Auth.login(credentials, Platform.current_tty) do |login|
      show_message(MESSAGE_ROW, Colors::SUCCESS, "Hi, #{login.account.name}.", panel_width)
      menu(panel_width, login)
    end
    return if failure.nil?

    show_message(MESSAGE_ROW, Colors::ERROR, failure.message, panel_width)
    sleep 2.seconds
  end

  private def draw_login_screen(keymap_failure : Failure?) : Int32
    Terminal.clear_screen
    right_col, rows = Terminal.draw_sidebar
    _, cols = Terminal.term_size
    bar_col = [cols // 5, 4].max
    panel_width = bar_col - 1 # usable columns in the left panel
    Terminal.draw_machine_details(right_col, rows)
    show_keymap_status(keymap_failure, panel_width)

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

  private def show_keymap_status(failure : Failure?, panel_width : Int32) : Nil
    if failure.nil?
      Terminal.draw_keyboard_layout(@keyboard_layout, panel_width)
      Logger.info("keyboard.layout_changed", "Keyboard layout changed", {layout: @keyboard_layout.keymap})
    else
      Logger.warn("keyboard.layout_change_failed", "Keyboard layout change failed", {layout: @keyboard_layout.keymap, error: failure.message})
      show_message(MESSAGE_ROW, Colors::ERROR, "layout failed: #{@keyboard_layout.label}", panel_width)
    end
  end

  private def show_message(row : Int32, color : String, text : String, width : Int32) : Nil
    STDOUT.print "\e[#{row};1H#{color}#{text[0, width].ljust(width)}#{Colors::RESET}"
    STDOUT.flush
  end

  # ── session menu ──────────────────────────────────────────────────────────
  private def menu(panel_width : Int32, login : Auth::Login) : Nil
    wm_sessions = Sessions.available_sessions(@config.xsession_dirs, @config.wayland_session_dirs)
    config_entries = @config.menu

    all_labels = wm_sessions.map(&.label) + config_entries.map(&.label)
    all_labels.each_with_index do |label, i|
      num = "#{Colors::NUMBER}#{i + 1})#{Colors::RESET}"
      lbl = "#{Colors::ITEM}#{label}#{Colors::RESET}"
      plain = "#{i + 1}) #{label}"
      pad = " " * [panel_width - plain.size, 0].max
      STDOUT.print "\e[#{MENU_ROW + i};1H#{num} #{lbl}#{pad}"
    end

    default = wm_sessions.empty? ? "" : "1"
    choice_row = MENU_ROW + all_labels.size + 1
    STDOUT.print "\e[#{choice_row};1H#{Colors::MUTED}Choice [#{default}]:#{Colors::RESET} "
    STDOUT.flush

    choice = (STDIN.gets(chomp: true) || "").strip
    choice = default if choice.empty?
    idx = (choice.to_i? || 0) - 1

    # Negative indexes would count from the end; anything out of range
    # simply returns to the login prompt.
    session = idx >= 0 ? wm_sessions[idx]? : nil
    entry = idx >= wm_sessions.size ? config_entries[idx - wm_sessions.size]? : nil

    if session
      case session.session_type
      in .x11?     then start_x11(login, session.exec, choice_row, panel_width)
      in .wayland? then run_session("wayland", login, Sessions.wayland(login.account, session.exec, @config.vt, @config.seat))
      end
    elsif entry
      dispatch_entry(entry, login, choice_row, panel_width)
    end
  end

  # X11 sessions run detached on their own VT; the greeter returns to the
  # login prompt immediately.
  private def start_x11(login : Auth::Login, wm_exec : String, choice_row : Int32, panel_width : Int32) : Nil
    SessionTracker.prune_finished
    vt = SessionTracker.next_vt
    if vt.nil?
      show_message(choice_row + 1, Colors::ERROR, "All session slots in use (max #{SessionTracker.capacity}).", panel_width)
      sleep 2.seconds
      return
    end

    launch = Sessions.x11(login.account, wm_exec, vt, @config.seat)
    return log_launch_failure("x11", login, launch) if launch.is_a?(Failure)

    pid = Supervisor.start(launch, login.pam)
    return log_launch_failure("x11", login, pid) if pid.is_a?(Failure)

    SessionTracker.add(pid, SessionTracker::Entry.new(vt, vt - SessionTracker::FIRST_VT, login.account.name))
  end

  # Every other session runs in the foreground; the greeter waits for it.
  private def run_session(kind : String, login : Auth::Login, launch : SessionPlan::Launch | Failure) : Nil
    return log_launch_failure(kind, login, launch) if launch.is_a?(Failure)

    pid = Supervisor.start(launch, login.pam)
    return log_launch_failure(kind, login, pid) if pid.is_a?(Failure)

    Supervisor.wait(pid)
    sleep 1.second
  end

  private def log_launch_failure(kind : String, login : Auth::Login, failure : Failure) : Nil
    Logger.error("session.#{kind}.launch_failed", "Session launch failed", {username: login.account.name, uid: login.account.uid, error: failure.message})
  end

  private def dispatch_entry(entry : MenuEntry, login : Auth::Login, choice_row : Int32, panel_width : Int32) : Nil
    case entry.action
    in .exit?
      login.pam.finish
      show_message(choice_row + 1, Colors::MUTED, "Goodbye.", panel_width)
      exit 0
    in .reboot?
      login.pam.finish
      show_message(choice_row + 1, Colors::ERROR, Platform.reboot.message, panel_width)
      sleep 2.seconds
    in .shutdown?
      login.pam.finish
      show_message(choice_row + 1, Colors::ERROR, Platform.shutdown.message, panel_width)
      sleep 2.seconds
    in .ssh?
      STDOUT.print "\e[#{choice_row + 1};1H#{Colors::PROMPT}Host:#{Colors::RESET} "
      STDOUT.flush
      host = (STDIN.gets(chomp: true) || "").strip
      run_session("ssh", login, Sessions.ssh(login.account, host)) unless host.empty?
    in .moonlight?
      tty = Platform.current_tty || Platform.tty_path(@config.vt)
      launch = Sessions.moonlight(login.account, entry.host || "localhost", tty, @config.vt, @config.seat)
      run_session("moonlight", login, launch)
    end
  end
end

Greeter.new(Config.load).run
