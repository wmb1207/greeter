require "./failure"
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
  record LoginInput, username : String, password : String, layout : KeyboardLayout
  CTRL_L    = 0x0c_u8
  BACKSPACE = 0x08_u8
  DELETE    = 0x7f_u8

  def self.prepare_display
    # The Linux console can start in a non-UTF-8 character set after systemd
    # resets the TTY. Select UTF-8/default G0 and shift back into G0 before
    # drawing box characters.
    STDOUT.print "\e%G\e(B\x0f"
  end

  def self.read_auth_inputs(layout : KeyboardLayout, panel_width : Int32) : LoginInput | Failure
    username_line = read_line_with_layout_toggle(5, "login:", false, layout, panel_width)
    return username_line if username_line.is_a?(Failure)

    username, layout = username_line
    username = username.strip
    return Failure.new("Empty username") if username.empty?

    password_line = read_line_with_layout_toggle(6, "Password:", true, layout, panel_width)
    return password_line if password_line.is_a?(Failure)

    password, layout = password_line
    return Failure.new("Empty password") if password.empty?

    LoginInput.new(username, password, layout)
  end

  # Feed one input byte into the line being edited.  `pending` holds the
  # bytes of a UTF-8 sequence that is not complete yet.  Returns the new
  # text and pending bytes; invalid sequences are dropped.
  def self.feed(text : String, pending : Bytes, byte : UInt8) : {String, Bytes}
    case byte
    when BACKSPACE, DELETE
      {text.rchop, Bytes.empty}
    else
      return {text, pending} if byte < 32

      bytes = Bytes.new(pending.size + 1)
      pending.copy_to(bytes)
      bytes[pending.size] = byte
      chunk = String.new(bytes)
      if chunk.valid_encoding?
        {text + chunk, Bytes.empty}
      elsif bytes.size >= 4
        {text, Bytes.empty}
      else
        {text, bytes}
      end
    end
  end

  def self.clear_screen
    # \e[2J → clear screen
    # \e[H  → move cursor to top-left
    prepare_display
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

  def self.wait_for_stable_size
    previous = term_size
    4.times do
      sleep 100.milliseconds
      current = term_size
      return if current == previous
      previous = current
    end
  end

  # Draw a full-height vertical bar at 20% of the terminal width.
  # Returns {right_col, rows} — right_col is where content should start.
  def self.draw_sidebar : {Int32, Int32}
    rows, cols = term_size
    bar_col = Math.max(cols // 5, 4)
    rows.times { |row| STDOUT.print "\e[#{row + 1};#{bar_col}H#{Colors::DIM}│#{Colors::RESET}" }
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

  private def self.read_line_with_layout_toggle(row : Int32, prompt : String, hidden : Bool, layout : KeyboardLayout, panel_width : Int32) : {String, KeyboardLayout} | Failure
    prompt_text = "#{prompt} "
    prompt_col = prompt_text.size + 1
    input_width = [panel_width - prompt_text.size, 1].max
    text = ""
    pending = Bytes.empty

    STDOUT.print "\e[#{row};1H#{Colors::PROMPT}#{prompt}#{Colors::RESET} "
    STDOUT.print " " * input_width
    STDOUT.print "\e[#{row};#{prompt_col}H"
    STDOUT.flush

    with_noncanonical_input do
      loop do
        byte = STDIN.read_byte
        return Failure.new("Input error") if byte.nil?

        case byte
        when 0x0d_u8, 0x0a_u8
          STDOUT.print "\e[#{row + 1};1H"
          STDOUT.flush
          return {text, layout}
        when CTRL_L
          next_layout = layout.toggle
          layout = next_layout if apply_keymap_feedback(next_layout, panel_width)
          redraw_input(row, prompt_col, input_width, text, hidden)
        else
          edited, pending = feed(text, pending, byte)
          next if edited == text

          text = edited
          redraw_input(row, prompt_col, input_width, text, hidden)
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

  def self.draw_login_prompt(panel_width : Int32)
    prompt = "login:"
    prompt_text = "#{prompt} "
    prompt_col = prompt_text.size + 1
    input_width = [panel_width - prompt_text.size, 1].max

    STDOUT.print "\e[5;1H#{Colors::PROMPT}#{prompt}#{Colors::RESET} "
    STDOUT.print " " * input_width
    STDOUT.print "\e[5;#{prompt_col}H"
    STDOUT.flush
  end

  def self.apply_keymap_feedback(layout : KeyboardLayout, panel_width : Int32) : Bool
    failure = Platform.apply_keymap(layout)
    if failure.nil?
      prepare_display
      draw_keyboard_layout(layout, panel_width)
      Logger.info("keyboard.layout_changed", "Keyboard layout changed", {layout: layout.keymap})
      true
    else
      Logger.warn("keyboard.layout_change_failed", "Keyboard layout change failed", {layout: layout.keymap, error: failure.message})
      msg = "layout failed: #{layout.label}"
      STDOUT.print "\e[8;1H#{Colors::ERROR}#{msg[0, panel_width].ljust(panel_width)}#{Colors::RESET}"
      STDOUT.flush
      false
    end
  end
end
