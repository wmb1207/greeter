require "./result"
require "./libs"
require "./action"
require "./logger"
require "./platform"

module Sessions
  TTY1 = Platform.tty_path(1)

  alias ActionResult = Result(Action)
  alias BooleanResult = Result(Bool)

  enum SessionType
    X11
    Wayland
  end

  struct DesktopSession
    getter name : String
    getter exec : String
    getter session_type : SessionType

    def initialize(@name, @exec, @session_type)
    end

    def label : String
      suffix = case @session_type
               in .x11?     then "X11"
               in .wayland? then "Wayland"
               end
      "#{@name} (#{suffix})"
    end
  end

  def self.available_sessions(xsession_dirs : Array(String), wayland_session_dirs : Array(String)) : Array(DesktopSession)
    sessions = [] of DesktopSession
    seen = Set(String).new

    add_sessions(sessions, seen, xsession_dirs, SessionType::X11)
    add_sessions(sessions, seen, wayland_session_dirs, SessionType::Wayland)

    sessions.sort_by { |session| {session.name, session.session_type.to_s} }
  end

  private def self.add_sessions(sessions : Array(DesktopSession), seen : Set(String), dirs : Array(String), session_type : SessionType)
    dirs.each do |dir|
      Dir.glob("#{dir}/*.desktop").sort.each do |path|
        next if seen.includes?(path)
        seen.add(path)
        s = parse_desktop_file(path, session_type)
        sessions << s if s
      end
    end
  end

  private def self.parse_desktop_file(path : String, session_type : SessionType) : DesktopSession?
    name = nil
    exec_val = nil
    in_entry = false

    File.each_line(path) do |line|
      line = line.strip
      if line == "[Desktop Entry]"
        in_entry = true
      elsif line.starts_with?('[')
        in_entry = false
      elsif in_entry
        if line.starts_with?("Name=") && name.nil?
          name = line[5..]
        elsif line.starts_with?("Exec=") && exec_val.nil?
          # Strip .desktop field codes (%F, %u, etc.) — unused in session files
          exec_val = line[5..].gsub(/%[A-Za-z]/, "").strip
        end
      end
    end

    return nil unless name && exec_val
    DesktopSession.new(name.not_nil!, exec_val.not_nil!, session_type)
  rescue
    nil
  end

  def self.session_path(home : String) : String
    Platform.session_path(home, File.basename(home))
  end

  def self.close_pam_session(pamh : LibPAM::PamHandle)
    # Close the PAM session (tears down the systemd-logind session, stops user
    # services) then end the transaction.
    LibPAM.pam_close_session(pamh, 0)
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
  end

  def self.env_vars(pamh : LibPAM::PamHandle, pw : LibC::Passwd, vt : Int32 = 1, seat : String = "seat0", session_type : String = "x11")
    user = String.new(pw.pw_name)
    home = String.new(pw.pw_dir)
    shell = String.new(pw.pw_shell)

    env = {
      "HOME"    => home,
      "USER"    => user,
      "SHELL"   => shell,
      "LOGNAME" => user,
      "PATH"    => session_path(home),
      "ENV"     => "#{home}/.kshrc",
      # Required by PipeWire / PulseAudio to locate their socket.
      # pam_open_session (via pam_systemd) creates this directory;
      # we set it explicitly so the child always has the right value.
      "XDG_RUNTIME_DIR" => Platform.runtime_dir(pw.pw_uid),
      # Standard location for the per-user systemd/D-Bus broker.  The session
      # runs with a cleared environment, so set it explicitly for audio clients
      # and other user services that need to activate through D-Bus.
      "DBUS_SESSION_BUS_ADDRESS" => "unix:path=/run/user/#{pw.pw_uid}/bus",
      # Force PulseAudio-compatible clients to use this user's PipeWire-Pulse
      # socket instead of stale X11 root properties, inherited PAM values, or
      # legacy ~/.config/pulse runtime links from another login.
      "PULSE_SERVER" => "unix:/run/user/#{pw.pw_uid}/pulse/native",
      # Tells systemd-logind / D-Bus what kind of session this is.
      "XDG_SESSION_TYPE"  => session_type,
      "XDG_SESSION_CLASS" => "user",
      "XDG_SEAT"          => seat,
      "XDG_VTNR"          => vt.to_s,
    }

    with_pam_env(env, pamh)
  end

  private def self.with_pam_env(base : Hash(String, String), pamh : LibPAM::PamHandle) : Hash(String, String)
    merged = base.dup
    env_vars_from_pam(pamh) { |k, v| merged[k] ||= v }
    merged
  end

  def self.launch_session(pw : LibC::Passwd, pamh : LibPAM::PamHandle, wm_exec : String, vt : Int32, seat : String = "seat0") : ActionResult
    local_env_vars = env_vars(pamh, pw, vt, seat)
    # Build a PATH for the child session.
    # On NixOS, tools like uname/expr/hexdump may only exist in nix store paths
    # not exposed via /run/current-system/sw/bin.  Find coreutils and util-linux
    # directly in /nix/store so startx can locate them regardless of profile state.
    nix_extra = [] of String
    ["coreutils", "util-linux", "xinit"].each do |pkg|
      Dir.glob("/nix/store/*-#{pkg}-*/bin").each { |d| nix_extra << d }
    end

    greeter_path = (ENV["PATH"]? || "").split(":").reject(&.empty?)
    local_session_path = (greeter_path + nix_extra + session_path(local_env_vars["HOME"]).split(":").reject(&.empty?)).uniq.join(":")

    startx_cmd = local_session_path.split(":")
      .map { |d| "#{d}/startx" }
      .find { |p| File::Info.executable?(p) }

    if startx_cmd.nil?
      Logger.error("session.x11.startx_missing", "startx command not found in session PATH", {username: local_env_vars["USER"], uid: pw.pw_uid})
      LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
      return ActionResult.error("Greeter: startx command not found in session PATH: #{local_session_path}")
    end

    # Tell pam_systemd which TTY and seat/VT this session belongs to.
    # These must be set BEFORE pam_open_session so logind registers the
    # session as Active=yes on the correct seat/VT.
    tty_str = Platform.tty_path(vt)
    tty_str.to_unsafe.as(Void*).tap do |ptr|
      LibPAM.pam_set_item(pamh, LibPAM::PAM_TTY, ptr)
    end
    ["XDG_SESSION_TYPE=x11", "XDG_SESSION_CLASS=user",
     "XDG_SEAT=#{seat}", "XDG_VTNR=#{vt}"].each do |kv|
      LibPAM.pam_putenv(pamh, kv)
    end

    display = vt - SessionTracker::FIRST_VT
    username = local_env_vars["USER"]

    Logger.info("session.x11.starting", "Starting X11 session", {username: username, uid: pw.pw_uid, session: wm_exec, vt: vt, display: display})

    pid = LibC.fork
    if pid == 0
      supervise_x11_session(pw, pamh, startx_cmd, wm_exec, vt, display, seat)
      exit(1)
    elsif pid < 0
      Logger.error("session.x11.fork_failed", "Could not fork X11 session", {username: username, uid: pw.pw_uid, session: wm_exec})
      LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
      return ActionResult.error("Greeter: fork failed")
    end

    # ── parent: record supervisor and return immediately ─────────────────────
    # The supervisor owns pam_open_session/pam_close_session for this login.
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    SessionTracker.add(pid, SessionTracker::Entry.new(vt, display, username))
    ActionResult.ok(Action::NO_ACTION)
  end

  def self.launch_wayland_session(pw : LibC::Passwd, pamh : LibPAM::PamHandle, session_exec : String, vt : Int32, seat : String = "seat0") : ActionResult
    local_env_vars = env_vars(pamh, pw, vt, seat, "wayland")
    username = local_env_vars["USER"]
    args = session_exec.split(' ', remove_empty: true)
    if args.empty?
      LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
      return ActionResult.error("Greeter: empty Wayland session command")
    end

    command = resolve_command(args.first, local_env_vars["PATH"])
    if command.nil?
      Logger.error("session.wayland.command_missing", "Wayland session command not found", {username: username, uid: pw.pw_uid, session: session_exec})
      LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
      return ActionResult.error("Greeter: Wayland command not found: #{args.first}")
    end

    tty_str = Platform.tty_path(vt)
    tty_str.to_unsafe.as(Void*).tap do |ptr|
      LibPAM.pam_set_item(pamh, LibPAM::PAM_TTY, ptr)
    end
    ["XDG_SESSION_TYPE=wayland", "XDG_SESSION_CLASS=user",
     "XDG_SEAT=#{seat}", "XDG_VTNR=#{vt}"].each do |kv|
      LibPAM.pam_putenv(pamh, kv)
    end

    ret = LibPAM.pam_open_session(pamh, 0)
    if ret != LibPAM::PAM_SUCCESS
      Logger.error("session.wayland.pam_open_failed", "PAM session could not open", {username: username, uid: pw.pw_uid, pam_code: ret})
      LibPAM.pam_end(pamh, ret)
      return ActionResult.error("Greeter: PAM session could not open")
    end

    Logger.info("session.wayland.starting", "Starting Wayland session", {username: username, uid: pw.pw_uid, session: session_exec, vt: vt})

    pid = LibC.fork
    if pid == 0
      do_start_wayland_session(pw, env_vars(pamh, pw, vt, seat, "wayland"), command, args, vt)
      exit(1)
    elsif pid < 0
      Logger.error("session.wayland.fork_failed", "Could not fork Wayland session", {username: username, uid: pw.pw_uid, session: session_exec})
      close_pam_session(pamh)
      return ActionResult.error("Greeter: fork failed")
    end

    raw_status = 0_i32
    LibC.waitpid(pid, pointerof(raw_status), 0)
    close_pam_session(pamh)

    exited = (raw_status & 0x7f) == 0
    exit_code = (raw_status >> 8) & 0xff
    if exited && exit_code == 0
      Logger.info("session.wayland.ended", "Wayland session ended", {username: username, uid: pw.pw_uid, session: session_exec, exit_code: exit_code})
    else
      Logger.warn("session.wayland.ended", "Wayland session exited abnormally", {username: username, uid: pw.pw_uid, session: session_exec, exit_code: exit_code})
    end
    sleep 1.second
    ActionResult.ok(Action::NO_ACTION)
  end

  private def self.resolve_command(command : String, path : String) : String?
    return command if command.includes?('/') && File::Info.executable?(command)

    path.split(":").reject(&.empty?)
      .map { |d| "#{d}/#{command}" }
      .find { |p| File::Info.executable?(p) }
  end

  private def self.do_start_wayland_session(pw : LibC::Passwd, env : Hash(String, String), command : String, args : Array(String), vt : Int32) : ActionResult
    LibC.chown(Platform.tty_path(vt), pw.pw_uid, pw.pw_gid)
    Platform.ensure_runtime_dir(pw.pw_uid, pw.pw_gid)

    return ActionResult.new(value: Action::EXIT_CODE_1, error: "Greeter: Privilege drop failed; session aborted") if drop_privileges(pw).is_error?
    Dir.cd(env["HOME"])

    begin
      Process.exec(
        command: command,
        args: args[1..],
        env: env,
        clear_env: true
      )
      ActionResult.ok(Action::NO_ACTION)
    rescue ex
      ActionResult.new(Action::EXIT_CODE_1, error: "Greeter: exec failed: #{ex.message}")
    end
  end

  # ═══════════════════════════════════════════════════════════════════════════════
  # SSH session launch
  # ═══════════════════════════════════════════════════════════════════════════════

  def self.launch_ssh(pw : LibC::Passwd, pamh : LibPAM::PamHandle, host : String) : ActionResult
    local_env_vars = env_vars(pamh, pw)
    ssh_cmd = session_path(local_env_vars["HOME"]).split(":")
      .map { |d| "#{d}/ssh" }
      .find { |p| File::Info.executable?(p) }

    if ssh_cmd.nil?
      Logger.error("session.ssh.command_missing", "ssh command not found in session PATH", {username: local_env_vars["USER"], uid: pw.pw_uid, host: host})
      return ActionResult.new(
        value: Action::EXIT_CODE_1,
        error: "Greeter: ssh not found in path"
      )
    end

    Logger.info("session.ssh.starting", "Starting SSH session", {username: local_env_vars["USER"], uid: pw.pw_uid, host: host})

    pid = LibC.fork
    if pid == 0
      ssh_session = do_start_ssh_session(pw, local_env_vars, ssh_cmd, host)
      return ssh_session if ssh_session
    elsif pid < 0
      Logger.error("session.ssh.fork_failed", "Could not fork SSH session", {username: local_env_vars["USER"], uid: pw.pw_uid, host: host})
      return ActionResult.new(value: Action::NO_ACTION, error: "Greeter: fork failed")
    end

    raw_status = 0_i32
    LibC.waitpid(pid, pointerof(raw_status), 0)
    exited = (raw_status & 0x7f) == 0
    exit_code = (raw_status >> 8) & 0xff
    if exited && exit_code == 0
      Logger.info("session.ssh.ended", "SSH session ended", {username: local_env_vars["USER"], uid: pw.pw_uid, host: host, exit_code: exit_code})
    else
      Logger.warn("session.ssh.ended", "SSH session exited abnormally", {username: local_env_vars["USER"], uid: pw.pw_uid, host: host, exit_code: exit_code})
    end
    sleep 1.second
    ActionResult.ok(Action::NO_ACTION)
  end

  private def self.do_start_ssh_session(pw : LibC::Passwd, env : Hash(String, String), ssh_cmd : String, host : String) : ActionResult
    Platform.ensure_runtime_dir(pw.pw_uid, pw.pw_gid)
    return ActionResult.new(value: Action::EXIT_CODE_1, error: "Greeter: Privilege drop pfailed; session aborted") if drop_privileges(pw).is_error?
    Dir.cd(env["HOME"])
    sshResult = ssh(env, ssh_cmd, env["USER"], host)
    return sshResult if sshResult.is_error?
    ActionResult.ok(Action::NO_ACTION)
  end

  private def self.drop_privileges(pw : LibC::Passwd) : BooleanResult
    return BooleanResult.new(value: false, error: "Greeter: initgroups failed") if LibC.initgroups(pw.pw_name, pw.pw_gid) != 0
    return BooleanResult.new(value: false, error: "Greeter: setgid(#{pw.pw_gid}) failed") if LibC.setgid(pw.pw_gid) != 0
    return BooleanResult.new(value: false, error: "Greeter: setuid(#{pw.pw_uid}) failed") if LibC.setuid(pw.pw_uid) != 0
    BooleanResult.ok(true)
  end

  private def self.do_start_session(pw : LibC::Passwd, env : Hash(String, String), startx_cmd : String, wm_exec : String, vt : Int32, display : Int32) : ActionResult
    LibC.chown(Platform.tty_path(vt), pw.pw_uid, pw.pw_gid)
    Platform.ensure_runtime_dir(pw.pw_uid, pw.pw_gid)

    return ActionResult.new(value: Action::EXIT_CODE_1, error: "Greeter: Privilege drop failed; session aborted") if drop_privileges(pw).is_error?
    Dir.cd(env["HOME"])
    launch_wm(env, startx_cmd, wm_exec, vt, display)
  end

  private def self.supervise_x11_session(pw : LibC::Passwd, pamh : LibPAM::PamHandle, startx_cmd : String, wm_exec : String, vt : Int32, display : Int32, seat : String)
    user = String.new(pw.pw_name)

    # Open PAM/logind in the per-session supervisor, not in the greeter parent.
    # Otherwise logind associates the first graphical login with the long-lived
    # greeter process and later users do not get /run/user/<uid>.
    ret = LibPAM.pam_open_session(pamh, 0)
    if ret != LibPAM::PAM_SUCCESS
      Logger.error("session.x11.pam_open_failed", "PAM session could not open", {username: user, uid: pw.pw_uid, pam_code: ret})
      LibPAM.pam_end(pamh, ret)
      exit(1)
    end
    Logger.info("session.x11.pam_opened", "PAM session opened", {username: user, uid: pw.pw_uid, vt: vt, display: display})

    session_env = env_vars(pamh, pw, vt, seat)
    pid = LibC.fork
    if pid == 0
      do_start_session(pw, session_env, startx_cmd, wm_exec, vt, display)
      exit(1)
    elsif pid < 0
      Logger.error("session.x11.fork_failed", "Could not fork X11 session worker", {username: user, uid: pw.pw_uid, session: wm_exec})
      close_pam_session(pamh)
      exit(1)
    end

    raw_status = 0_i32
    LibC.waitpid(pid, pointerof(raw_status), 0)
    close_pam_session(pamh)

    if (raw_status & 0x7f) == 0
      exit((raw_status >> 8) & 0xff)
    else
      exit(128 + (raw_status & 0x7f))
    end
  end

  def self.launch_wm(env : Hash(String, String), startx_cmd : String, wm_exec : String, vt : Int32, display : Int32) : ActionResult
    # Prefer ~/.xsession (generated by home-manager) so that user-session
    # systemd targets (hm-graphical-session.target) are started correctly.
    # Fall back to wm_exec when no .xsession is present.
    home = env["HOME"]?
    xsession = home ? "#{home}/.xsession" : nil
    client = (xsession && File::Info.executable?(xsession)) ? xsession : wm_exec

    wm_args = client.split(' ', remove_empty: true)
    begin
      Process.exec(
        command: startx_cmd,
        args: wm_args + ["--", ":#{display}", "vt#{vt}"],
        env: env,
        clear_env: true
      )
      ActionResult.ok(Action::NO_ACTION)
    rescue ex
      ActionResult.new(Action::EXIT_CODE_1, error: "Greeter: exec failed: #{ex.message}")
    end
  end

  def self.ssh(env : Hash(String, String), ssh_cmd : String, user : String, host : String) : ActionResult
    begin
      Process.exec(
        command: ssh_cmd,
        args: ["-l", user, host],
        env: {
          "HOME"  => env["HOME"],
          "USER"  => env["USER"],
          "SHELL" => env["SHELL"],
          "PATH"  => session_path(env["HOME"]),
          "TERM"  => ENV["TERM"]? || Platform.term,
        },
        clear_env: true
      )
    rescue ex
      ActionResult.new(Action::EXIT_CODE_1, error: "Greeter: exec failed: #{ex.message}")
    end
  end

  private def self.env_vars_from_pam(pamh : LibPAM::PamHandle, & : String, String ->)
    raw_env_list = LibPAM.pam_getenvlist(pamh)
    # Return if it's null
    return {} of String => String if raw_env_list.null?

    i = 0
    while !(ptr = raw_env_list[i]).null?
      pair = String.new(ptr)
      if eq = pair.index('=')
        yield pair[0...eq], pair[(eq + 1)..]
      end
      i += 1
    end
  end
end
