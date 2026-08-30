require "./result"
require "./keyboard_layout"
require "./platform"
require "./logger"

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
  INFO    = "\e[38;5;244m"   # soft gray — right-side machine details
end

module Terminal
  alias Credentials = Result({String, String, KeyboardLayout})
  CTRL_L    = '\f'
  BACKSPACE = '\b'
  DELETE    = '\u007f'

  def self.read_auth_inputs(layout : KeyboardLayout, panel_width : Int32) : Credentials
    username_result = read_line_with_layout_toggle(5, "login:", false, layout, panel_width)
    return Credentials.error(username_result.error.not_nil!) unless username_result.is_ok?

    username, layout = username_result.value.not_nil!
    username = username.strip
    return Credentials.error("Empty username") if username.empty?

    password_result = read_line_with_layout_toggle(6, "Password:", true, layout, panel_width)
    return Credentials.error(password_result.error.not_nil!) unless password_result.is_ok?

    password, layout = password_result.value.not_nil!
    return Credentials.error("Empty password") if password.empty?

    Credentials.ok({username, password, layout})
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

  def self.draw_machine_details(left_col : Int32, rows : Int32)
    _, cols = term_size
    width = cols - left_col + 1
    return if width < 18 || rows < 4

    details = Platform.machine_details
    return if details.empty?

    title = "machine"
    STDOUT.print "\e[2;#{left_col}H#{Colors::TITLE}#{title[0, width].ljust(width)}#{Colors::RESET}"

    details.first(rows - 4).each_with_index do |(label, value), i|
      row = 4 + i
      prefix = label.empty? ? "  " : "#{label}: "
      available = [width - prefix.size, 1].max
      line = "#{Colors::MUTED}#{prefix}#{Colors::RESET}#{Colors::INFO}#{value[0, available]}#{Colors::RESET}"
      STDOUT.print "\e[#{row};#{left_col}H#{line}"
    end

    STDOUT.flush
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

  private alias LineResult = Result({String, KeyboardLayout})

  private def self.read_line_with_layout_toggle(row : Int32, prompt : String, hidden : Bool, layout : KeyboardLayout, panel_width : Int32) : LineResult
    prompt_text = "#{prompt} "
    prompt_col = prompt_text.size + 1
    input_width = [panel_width - prompt_text.size, 1].max
    buffer = String.build { }

    STDOUT.print "\e[#{row};1H#{Colors::PROMPT}#{prompt}#{Colors::RESET} "
    STDOUT.print " " * input_width
    STDOUT.print "\e[#{row};#{prompt_col}H"
    STDOUT.flush

    with_noncanonical_input do
      loop do
        char = STDIN.read_char
        return LineResult.error("Input error") if char.nil?

        case char
        when '\r', '\n'
          STDOUT.print "\e[#{row + 1};1H"
          STDOUT.flush
          return LineResult.ok({buffer, layout})
        when CTRL_L
          next_layout = layout.toggle
          layout = next_layout if apply_keymap_feedback(next_layout, panel_width)
          redraw_input(row, prompt_col, input_width, buffer, hidden)
        when BACKSPACE, DELETE
          unless buffer.empty?
            buffer = buffer[0, buffer.size - 1]
            redraw_input(row, prompt_col, input_width, buffer, hidden)
          end
        else
          next if char.ord < 32
          buffer += char.to_s
          redraw_input(row, prompt_col, input_width, buffer, hidden)
        end
      end
    end
  end

  private def self.with_noncanonical_input(&)
    fd = STDIN.fd
    old_term = LibC::Termios.new
    LibC.tcgetattr(fd, pointerof(old_term))

    begin
      raw = old_term
      raw.c_lflag = old_term.c_lflag & ~(LibC::ECHO | LibC::ICANON).to_u32
      raw.c_cc[LibC::VMIN] = 1
      raw.c_cc[LibC::VTIME] = 0
      LibC.tcsetattr(fd, LibC::TCSANOW, pointerof(raw))
      yield
    ensure
      LibC.tcsetattr(fd, LibC::TCSANOW, pointerof(old_term))
    end
  end

  private def self.redraw_input(row : Int32, prompt_col : Int32, input_width : Int32, buffer : String, hidden : Bool)
    visible = hidden ? "*" * buffer.size : buffer
    visible = visible[-input_width, input_width] if visible.size > input_width
    STDOUT.print "\e[#{row};#{prompt_col}H#{visible.ljust(input_width)}"
    cursor_col = prompt_col + [visible.size, input_width].min
    STDOUT.print "\e[#{row};#{cursor_col}H"
    STDOUT.flush
  end

  def self.draw_keyboard_layout(layout : KeyboardLayout, panel_width : Int32)
    text = "layout: #{layout.label}"
    STDOUT.print "\e[4;1H#{Colors::MUTED}#{text[0, panel_width].ljust(panel_width)}#{Colors::RESET}"
    STDOUT.flush
  end

  def self.apply_keymap_feedback(layout : KeyboardLayout, panel_width : Int32) : Bool
    result = Platform.apply_keymap(layout)
    if result.is_ok?
      draw_keyboard_layout(layout, panel_width)
      Logger.info("keyboard.layout_changed", "Keyboard layout changed", {layout: layout.keymap})
      true
    else
      Logger.warn("keyboard.layout_change_failed", "Keyboard layout change failed", {layout: layout.keymap, error: result.error})
      msg = "layout failed: #{layout.label}"
      STDOUT.print "\e[8;1H#{Colors::ERROR}#{msg[0, panel_width].ljust(panel_width)}#{Colors::RESET}"
      STDOUT.flush
      false
    end
  end

  def self.menu
  end
end
