require "./result"

# ANSI 256-color codes — Nord-earthy palette.
# 66  dusty teal-slate  → borders / structural lines
# 223 warm cream        → title (bold)
# 240 charcoal gray     → sidebar dim bar
# 109 dusty slate-blue  → prompts (login / password)
# 136 ochre/amber       → menu index numbers
# 144 warm khaki        → menu labels
# 106 moss green        → success / welcome messages
# 130 terracotta rust   → auth failure / errors
# 101 olive-gray        → muted choice prompt
module Colors
  RESET   = "\e[0m"
  BORDER  = "\e[38;5;66m"    # dusty teal-slate — box lines and sidebar
  TITLE   = "\e[1;38;5;223m" # warm cream, bold — header title
  DIM     = "\e[38;5;240m"   # charcoal gray — sidebar bar
  PROMPT  = "\e[38;5;109m"   # dusty slate-blue — "login:" / "Password:"
  NUMBER  = "\e[38;5;136m"   # ochre/amber — menu index numbers
  ITEM    = "\e[38;5;144m"   # warm khaki — menu labels
  SUCCESS = "\e[38;5;106m"   # moss green — welcome / ok messages
  ERROR   = "\e[38;5;130m"   # terracotta rust — auth failure
  MUTED   = "\e[38;5;101m"   # olive-gray — choice prompt
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
