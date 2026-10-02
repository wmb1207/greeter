require "./result"
require "./libs"
require "./action"
require "./logger"
require "./platform"
require "./account"
require "./session_tracker"

module Sessions
  alias ActionResult = Result(Action)

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

  # ═══════════════════════════════════════════════════════════════════════════════
  # PAM session lifecycle
  # ═══════════════════════════════════════════════════════════════════════════════

  # Establish credentials and open the session.  Returns the PAM status; on
  # failure the credentials are already deleted and the caller only has to
  # pam_end.
  def self.open_pam_session(pamh : LibPAM::PamHandle) : Int32
    ret = LibPAM.pam_setcred(pamh, LibPAM::PAM_ESTABLISH_CRED)
    return ret unless ret == LibPAM::PAM_SUCCESS

    ret = LibPAM.pam_open_session(pamh, 0)
    LibPAM.pam_setcred(pamh, LibPAM::PAM_DELETE_CRED) unless ret == LibPAM::PAM_SUCCESS
    ret
  end

  def self.close_pam_session(pamh : LibPAM::PamHandle)
    # Close the PAM session (tears down the systemd-logind session, stops user
    # services), drop credentials, then end the transaction.
    LibPAM.pam_close_session(pamh, 0)
    LibPAM.pam_setcred(pamh, LibPAM::PAM_DELETE_CRED)
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
  end

  # ═══════════════════════════════════════════════════════════════════════════════
  # Forked children
  # ═══════════════════════════════════════════════════════════════════════════════
  #
  # A forked child must never return into the greeter: it would run a second
  # greeter loop on the same TTY (as root if the privilege drop failed).  The
  # block is expected to exec; any exception or fall-through ends the child
  # with _exit, which also skips at_exit handlers and the flushing of stdio
  # buffers inherited from the parent.
  def self.in_child(event : String, &) : NoReturn
    yield
    Logger.error(event, "Session child returned without exec")
    LibC._exit(1)
  rescue ex
    Logger.error(event, "Session child failed", {error: ex.message})
    LibC._exit(1)
  end

  # Order is mandatory: initgroups → setgid → setuid.  setuid must come last:
  # once a process drops to an unprivileged UID it can no longer alter its GID
  # or supplementary groups on Linux.
  def self.drop_privileges(account : Account) : Bool
    if LibC.initgroups(account.name, account.gid) != 0
      Logger.error("privileges.initgroups_failed", "Could not initialize supplementary groups", {uid: account.uid})
      return false
    end
    if LibC.setgid(account.gid) != 0
      Logger.error("privileges.setgid_failed", "Could not set process gid", {uid: account.uid, gid: account.gid})
      return false
    end
    if LibC.setuid(account.uid) != 0
      Logger.error("privileges.setuid_failed", "Could not set process uid", {uid: account.uid})
      return false
    end
    true
  end

  # Block until `pid` exits.  Returns nil if the child was already reaped
  # elsewhere (the status is then unknown).
  def self.wait_child(pid : Int32) : Process::Status?
    raw = 0_i32
    LibC.waitpid(pid, pointerof(raw), 0) == pid ? Process::Status.new(raw) : nil
  end

  def self.log_session_end(kind : String, status : Process::Status?, fields : NamedTuple) : Nil
    event = "session.#{kind}.ended"
    if status.nil?
      Logger.warn(event, "Session ended with unknown status", fields)
    elsif (code = status.exit_code?) && code == 0
      Logger.info(event, "Session ended", fields.merge(exit_code: code))
    elsif code
      Logger.warn(event, "Session exited abnormally", fields.merge(exit_code: code))
    else
      Logger.warn(event, "Session terminated by signal", fields.merge(signal: status.exit_signal?.try(&.value)))
    end
  end

  def self.env_vars(pamh : LibPAM::PamHandle, account : Account, vt : Int32 = 1, seat : String = "seat0", session_type : String = "x11")
    env = {
      "HOME"    => account.home,
      "USER"    => account.name,
      "SHELL"   => account.shell,
      "LOGNAME" => account.name,
      "PATH"    => session_path(account.home),
      "ENV"     => "#{account.home}/.kshrc",
      # Required by PipeWire / PulseAudio to locate their socket.
      # pam_open_session (via pam_systemd) creates this directory;
      # we set it explicitly so the child always has the right value.
      "XDG_RUNTIME_DIR" => Platform.runtime_dir(account.uid),
      # Standard location for the per-user systemd/D-Bus broker.  The session
      # runs with a cleared environment, so set it explicitly for audio clients
      # and other user services that need to activate through D-Bus.
      "DBUS_SESSION_BUS_ADDRESS" => "unix:path=/run/user/#{account.uid}/bus",
      # Force PulseAudio-compatible clients to use this user's PipeWire-Pulse
      # socket instead of stale X11 root properties, inherited PAM values, or
      # legacy ~/.config/pulse runtime links from another login.
      "PULSE_SERVER" => "unix:/run/user/#{account.uid}/pulse/native",
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

  # ═══════════════════════════════════════════════════════════════════════════════
  # X11 session launch
  # ═══════════════════════════════════════════════════════════════════════════════

  def self.launch_session(account : Account, pamh : LibPAM::PamHandle, wm_exec : String, vt : Int32, seat : String = "seat0") : ActionResult
    local_env_vars = env_vars(pamh, account, vt, seat)
    # Build a PATH for the child session.
    # On NixOS, tools like uname/expr/hexdump may only exist in nix store paths
    # not exposed via /run/current-system/sw/bin.  Find coreutils and util-linux
    # directly in /nix/store so startx can locate them regardless of profile state.
    nix_extra = [] of String
    ["coreutils", "util-linux", "xinit"].each do |pkg|
      Dir.glob("/nix/store/*-#{pkg}-*/bin").each { |d| nix_extra << d }
    end

    greeter_path = (ENV["PATH"]? || "").split(":").reject(&.empty?)
    local_session_path = (greeter_path + nix_extra + session_path(account.home).split(":").reject(&.empty?)).uniq.join(":")

    startx_cmd = local_session_path.split(":")
      .map { |d| "#{d}/startx" }
      .find { |p| File::Info.executable?(p) }

    if startx_cmd.nil?
      Logger.error("session.x11.startx_missing", "startx command not found in session PATH", {username: account.name, uid: account.uid})
      LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
      return ActionResult.error("Greeter: startx command not found in session PATH: #{local_session_path}")
    end

    set_pam_session_items(pamh, "x11", vt, seat)

    display = vt - SessionTracker::FIRST_VT

    Logger.info("session.x11.starting", "Starting X11 session", {username: account.name, uid: account.uid, session: wm_exec, vt: vt, display: display})

    pid = LibC.fork
    if pid == 0
      supervise_x11_session(account, pamh, startx_cmd, wm_exec, vt, display, seat)
    elsif pid < 0
      Logger.error("session.x11.fork_failed", "Could not fork X11 session", {username: account.name, uid: account.uid, session: wm_exec})
      LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
      return ActionResult.error("Greeter: fork failed")
    end

    # ── parent: record supervisor and return immediately ─────────────────────
    # The supervisor owns pam_open_session/pam_close_session for this login.
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    SessionTracker.add(pid, SessionTracker::Entry.new(vt, display, account.name))
    ActionResult.ok(Action::NO_ACTION)
  end

  # Runs in the forked per-login supervisor; never returns.
  private def self.supervise_x11_session(account : Account, pamh : LibPAM::PamHandle, startx_cmd : String, wm_exec : String, vt : Int32, display : Int32, seat : String) : NoReturn
    in_child("session.x11.supervisor_failed") do
      # Open PAM/logind in the per-session supervisor, not in the greeter parent.
      # Otherwise logind associates the first graphical login with the long-lived
      # greeter process and later users do not get /run/user/<uid>.
      ret = open_pam_session(pamh)
      if ret != LibPAM::PAM_SUCCESS
        Logger.error("session.x11.pam_open_failed", "PAM session could not open", {username: account.name, uid: account.uid, pam_code: ret})
        LibPAM.pam_end(pamh, ret)
        LibC._exit(1)
      end
      Logger.info("session.x11.pam_opened", "PAM session opened", {username: account.name, uid: account.uid, vt: vt, display: display})

      session_env = env_vars(pamh, account, vt, seat)
      pid = LibC.fork
      if pid == 0
        in_child("session.x11.exec_failed") do
          prepare_user_child(account, Platform.tty_path(vt))
          exec_startx(session_env, startx_cmd, wm_exec, vt, display)
        end
      elsif pid < 0
        Logger.error("session.x11.fork_failed", "Could not fork X11 session worker", {username: account.name, uid: account.uid, session: wm_exec})
        close_pam_session(pamh)
        LibC._exit(1)
      end

      status = wait_child(pid)
      close_pam_session(pamh)
      Platform.restore_tty(Platform.tty_path(vt))
      log_session_end("x11", status, {username: account.name, vt: vt, display: display, pid: pid})

      LibC._exit(status.try(&.exit_code?) || 1)
    end
  end

  private def self.exec_startx(env : Hash(String, String), startx_cmd : String, wm_exec : String, vt : Int32, display : Int32) : NoReturn
    # Prefer ~/.xsession (generated by home-manager) so that user-session
    # systemd targets (hm-graphical-session.target) are started correctly.
    # Fall back to wm_exec when no .xsession is present.
    xsession = "#{env["HOME"]}/.xsession"
    client = File::Info.executable?(xsession) ? xsession : wm_exec

    Process.exec(
      command: startx_cmd,
      args: client.split(' ', remove_empty: true) + ["--", ":#{display}", "vt#{vt}"],
      env: env,
      clear_env: true
    )
  end

  # ═══════════════════════════════════════════════════════════════════════════════
  # Wayland session launch
  # ═══════════════════════════════════════════════════════════════════════════════

  def self.launch_wayland_session(account : Account, pamh : LibPAM::PamHandle, session_exec : String, vt : Int32, seat : String = "seat0") : ActionResult
    username = account.name
    args = session_exec.split(' ', remove_empty: true)
    if args.empty?
      LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
      return ActionResult.error("Greeter: empty Wayland session command")
    end

    command = resolve_command(args.first, session_path(account.home))
    if command.nil?
      Logger.error("session.wayland.command_missing", "Wayland session command not found", {username: username, uid: account.uid, session: session_exec})
      LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
      return ActionResult.error("Greeter: Wayland command not found: #{args.first}")
    end

    set_pam_session_items(pamh, "wayland", vt, seat)

    ret = open_pam_session(pamh)
    if ret != LibPAM::PAM_SUCCESS
      Logger.error("session.wayland.pam_open_failed", "PAM session could not open", {username: username, uid: account.uid, pam_code: ret})
      LibPAM.pam_end(pamh, ret)
      return ActionResult.error("Greeter: PAM session could not open")
    end

    Logger.info("session.wayland.starting", "Starting Wayland session", {username: username, uid: account.uid, session: session_exec, vt: vt})

    env = env_vars(pamh, account, vt, seat, "wayland")
    tty = Platform.tty_path(vt)
    pid = LibC.fork
    if pid == 0
      in_child("session.wayland.exec_failed") do
        prepare_user_child(account, tty)
        Process.exec(command: command, args: args[1..], env: env, clear_env: true)
      end
    elsif pid < 0
      Logger.error("session.wayland.fork_failed", "Could not fork Wayland session", {username: username, uid: account.uid, session: session_exec})
      close_pam_session(pamh)
      return ActionResult.error("Greeter: fork failed")
    end

    status = wait_child(pid)
    close_pam_session(pamh)
    Platform.restore_tty(tty)
    log_session_end("wayland", status, {username: username, uid: account.uid, session: session_exec})
    sleep 1.second
    ActionResult.ok(Action::NO_ACTION)
  end

  private def self.resolve_command(command : String, path : String) : String?
    return command if command.includes?('/') && File::Info.executable?(command)

    path.split(":").reject(&.empty?)
      .map { |d| "#{d}/#{command}" }
      .find { |p| File::Info.executable?(p) }
  end

  # ═══════════════════════════════════════════════════════════════════════════════
  # SSH session launch
  # ═══════════════════════════════════════════════════════════════════════════════
  #
  # Runs on the greeter's own TTY and opens no PAM session; the handle is
  # ended here once ssh exits.  On error the caller ends it.

  def self.launch_ssh(account : Account, pamh : LibPAM::PamHandle, host : String) : ActionResult
    path = session_path(account.home)
    ssh_cmd = resolve_command("ssh", path)

    if ssh_cmd.nil?
      Logger.error("session.ssh.command_missing", "ssh command not found in session PATH", {username: account.name, uid: account.uid, host: host})
      return ActionResult.error("Greeter: ssh not found in path")
    end

    Logger.info("session.ssh.starting", "Starting SSH session", {username: account.name, uid: account.uid, host: host})

    env = {
      "HOME"  => account.home,
      "USER"  => account.name,
      "SHELL" => account.shell,
      "PATH"  => path,
      "TERM"  => ENV["TERM"]? || Platform.term,
    }

    pid = LibC.fork
    if pid == 0
      in_child("session.ssh.exec_failed") do
        Platform.ensure_runtime_dir(account.uid, account.gid)
        LibC._exit(1) unless drop_privileges(account)
        Dir.cd(account.home)
        Process.exec(command: ssh_cmd, args: ["-l", account.name, host], env: env, clear_env: true)
      end
    elsif pid < 0
      Logger.error("session.ssh.fork_failed", "Could not fork SSH session", {username: account.name, uid: account.uid, host: host})
      return ActionResult.error("Greeter: fork failed")
    end

    status = wait_child(pid)
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    log_session_end("ssh", status, {username: account.name, uid: account.uid, host: host})
    sleep 1.second
    ActionResult.ok(Action::NO_ACTION)
  end

  # ═══════════════════════════════════════════════════════════════════════════════
  # Shared helpers
  # ═══════════════════════════════════════════════════════════════════════════════

  # Tell pam_systemd which TTY and seat/VT this session belongs to.  These
  # must be set BEFORE pam_open_session so logind registers the session as
  # Active=yes on the correct seat/VT.
  def self.set_pam_session_items(pamh : LibPAM::PamHandle, session_type : String, vt : Int32, seat : String)
    LibPAM.pam_set_item(pamh, LibPAM::PAM_TTY, Platform.tty_path(vt).to_unsafe.as(Void*))
    ["XDG_SESSION_TYPE=#{session_type}", "XDG_SESSION_CLASS=user",
     "XDG_SEAT=#{seat}", "XDG_VTNR=#{vt}"].each do |kv|
      LibPAM.pam_putenv(pamh, kv)
    end
  end

  # Child-side setup before exec: hand the VT to the user (restored by the
  # parent with Platform.restore_tty), then drop privileges.
  def self.prepare_user_child(account : Account, tty : String) : Nil
    LibC.chown(tty, account.uid, account.gid)
    Platform.ensure_runtime_dir(account.uid, account.gid)
    LibC._exit(1) unless drop_privileges(account)
    Dir.cd(account.home)
  end

  def self.env_vars_from_pam(pamh : LibPAM::PamHandle, & : String, String ->) : Nil
    raw_env_list = LibPAM.pam_getenvlist(pamh)
    return if raw_env_list.null?

    # The array and every string are malloc-allocated; we own and free them.
    i = 0
    while !(ptr = raw_env_list[i]).null?
      pair = String.new(ptr)
      if eq = pair.index('=')
        yield pair[0...eq], pair[(eq + 1)..]
      end
      LibC.free(ptr.as(Void*))
      i += 1
    end
    LibC.free(raw_env_list.as(Void*))
  end
end
