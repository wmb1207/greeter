require "./result"

module Terminal

  alias Credentials = Result({String, String})
  def self.read_auth_inputs : Credentials
    STDOUT.print "\e[5;1Hlogin: "
    STDOUT.flush
    username = STDIN.gets(chomp: true)
    return Credentials.error("Empty username") if username.nil? || username.strip.empty?
    username = username.strip

    STDOUT.print "\e[6;1HPassword: "
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
    rows.times { |r| STDOUT.print "\e[#{r + 1};#{bar_col}H│" }
    STDOUT.flush
    {bar_col + 2, rows}
  end

  # Query the terminal dimensions via TIOCGWINSZ.
  # Falls back to 24x80 if the ioctl fails (e.g. redirected stdio).
  def self.term_size : {Int32, Int32}
    ws = LibC::Winsize.new
    ret = LibC.ioctl(STDOUT.fd, LibC::TIOCGWINSZ, pointerof(ws))
    (ret == 0 && ws.ws_col > 0) ? {ws.ws_row.to_i, ws.ws_col.to_i} : {24, 80}
  end

  def self.draw_sidebar : {Int32, Int32}
    rows, cols = term_size
    bar_col = Math.max(cols // 5, 4)
    rows.times { |r| STDOUT.print "\e[#{r + 1};#{bar_col}H│" }
    STDOUT.flush
    {bar_col + 2, rows}
  end

  def self.read_password : String
    fd       = STDIN.fd
    old_term = LibC::Termios.new
    LibC.tcgetattr(fd, pointerof(old_term))

    begin
      silent        = old_term
      # Clear the ECHO flag to suppress character echo.
      silent.c_lflag = old_term.c_lflag & ~LibC::ECHO.to_u32
      LibC.tcsetattr(fd, LibC::TCSANOW, pointerof(silent))
      STDIN.gets(chomp: true) || ""
    ensure
      # Restore original terminal settings unconditionally.
      LibC.tcsetattr(fd, LibC::TCSANOW, pointerof(old_term))
    end
  end

  def self.menu()
  end
end
