require "./result"

# ANSI color codes mapped to the creamsody-darker 16-color palette.
# color4  (#4a6a78) active steel-blue  → \e[34m / \e[94m bright variant #5a7888
# color6  (#4a7070) teal               → \e[36m  (borders)
# color7  (#9a9888) activeAlt gray     → \e[37m  (normal text / menu items)
# color8  (#3a3830) dark gray          → \e[90m  (dim / sidebar)
# color9  (#9a5035) orange-red         → \e[91m  (errors)
# color10 (#7a8060) sage green         → \e[92m  (success / welcome)
# color11 (#9a8050) gold               → \e[93m  (menu numbers)
# color12 (#5a7888) light blue         → \e[94m  (prompts)
# color15 (#b5b2a0) foreground warm-wh → \e[97m  (title)
module Colors
  RESET   = "\e[0m"
  BORDER  = "\e[36m"    # color6  teal — box lines and sidebar
  TITLE   = "\e[1;97m"  # bold color15 — header title
  DIM     = "\e[90m"    # color8  dark gray — sidebar bar
  PROMPT  = "\e[94m"    # color12 light blue — "login:" / "Password:"
  NUMBER  = "\e[93m"    # color11 gold — menu index numbers
  ITEM    = "\e[37m"    # color7  activeAlt — menu labels
  SUCCESS = "\e[92m"    # color10 sage green — welcome / ok messages
  ERROR   = "\e[91m"    # color9  orange-red — auth failure
  MUTED   = "\e[90m"    # color8  dark gray — choice prompt
end

module Terminal
  alias Credentials = Result({String, String})

  def self.read_auth_inputs : Credentials
    STDOUT.print "\e[5;1H#{Colors::PROMPT}login:#{Colors::RESET} "
    STDOUT.flush
    username = STDIN.gets(chomp: true)
    return Credentials.error("Empty username") if username.nil? || username.strip.empty?
    username = username.strip

    STDOUT.print "\e[6;1H#{Colors::PROMPT}Password:#{Colors::RESET} "
    STDOUT.flush
    password = read_password
    return Credentials.error("Empty password") if password.empty?

    Credentials.ok({username, password})
  end

  def self.clear_screen
    # \e[2J → clear screen
    # \e[H  → move cursor to top-left
    STDOUT.print "\e[2J\e[H"
    STDOUT.flush
  end

  # Query the terminal dimensions via TIOCGWINSZ.
  # Falls back to 24x80 if the ioctl fails (e.g. redirected stdio).
  def self.term_size : {Int32, Int32}
    ws = LibC::Winsize.new
    ret = LibC.ioctl(STDOUT.fd, LibC::TIOCGWINSZ, pointerof(ws))
    (ret == 0 && ws.ws_col > 0) ? {ws.ws_row.to_i, ws.ws_col.to_i} : {24, 80}
  end

  # Draw a full-height vertical bar at 20% of the terminal width.
  # Returns {right_col, rows} — right_col is where content should start.
  def self.draw_sidebar : {Int32, Int32}
    rows, cols = term_size
    bar_col = Math.max(cols // 5, 4)
    rows.times { |r| STDOUT.print "\e[#{r + 1};#{bar_col}H#{Colors::DIM}│#{Colors::RESET}" }
    STDOUT.flush
    {bar_col + 2, rows}
  end

  def self.read_password : String
    fd = STDIN.fd
    old_term = LibC::Termios.new
    LibC.tcgetattr(fd, pointerof(old_term))

    begin
      silent = old_term
      # Clear the ECHO flag to suppress character echo.
      silent.c_lflag = old_term.c_lflag & ~LibC::ECHO.to_u32
      LibC.tcsetattr(fd, LibC::TCSANOW, pointerof(silent))
      STDIN.gets(chomp: true) || ""
    ensure
      # Restore original terminal settings unconditionally.
      LibC.tcsetattr(fd, LibC::TCSANOW, pointerof(old_term))
    end
  end

  def self.menu
  end
end
