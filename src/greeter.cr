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
require "io/console"   # pulls in LibC::Termios, ECHO, TCSANOW, tcgetattr, tcsetattr

# ═══════════════════════════════════════════════════════════════════════════════
# LibPAM — FFI bindings for Linux-PAM
# ═══════════════════════════════════════════════════════════════════════════════
#
# Authentication happens in three steps:
#   1. pam_start       – open a transaction for the "login" service
#   2. pam_authenticate – verify credentials via the conversation callback
#   3. pam_acct_mgmt   – confirm the account is valid (not expired/locked)
#   4. pam_end         – release the transaction (always called)
#
# The conversation callback is how PAM asks the application for credentials.
# When PAM needs a password it calls our function with PAM_PROMPT_ECHO_OFF;
# we return whatever is in appdata_ptr.  We pass the password through
# appdata_ptr (a Box'd String) so no global state is needed.

@[Link("pam")]
lib LibPAM
  PAM_SUCCESS         =  0
  PAM_PROMPT_ECHO_OFF =  1   # silent prompt  → password
  PAM_PROMPT_ECHO_ON  =  2   # visible prompt → other credentials
  PAM_ERROR_MSG       =  3
  PAM_TEXT_INFO       =  4

  # One message PAM sends to the application (e.g. "Password: ").
  struct PamMessage
    msg_style : Int32
    msg       : UInt8*
  end

  # The application's reply to one PamMessage.
  # `resp` must be malloc-allocated; PAM (or pam_end) will free() it.
  struct PamResponse
    resp         : UInt8*
    resp_retcode : Int32    # unused by Linux-PAM, must be 0
  end

  # Passed to pam_start.  `conv` is our callback; `appdata_ptr` is
  # threaded through opaquely so the callback can reach application data.
  struct PamConv
    conv        : (Int32, PamMessage**, PamResponse**, Void*) -> Int32
    appdata_ptr : Void*
  end

  type PamHandle = Void*

  fun pam_start(service : UInt8*, user : UInt8*,
                conv : PamConv*, pamh : PamHandle*) : Int32
  fun pam_authenticate(pamh : PamHandle, flags : Int32) : Int32
  fun pam_acct_mgmt(pamh : PamHandle, flags : Int32) : Int32
  fun pam_open_session(pamh : PamHandle, flags : Int32) : Int32
  fun pam_close_session(pamh : PamHandle, flags : Int32) : Int32
  fun pam_end(pamh : PamHandle, status : Int32) : Int32
  fun pam_strerror(pamh : PamHandle, errnum : Int32) : UInt8*
  # Returns a null-terminated array of "KEY=VALUE" strings representing
  # all environment variables set by PAM modules (e.g. pam_systemd sets
  # XDG_SESSION_ID, DBUS_SESSION_BUS_ADDRESS, etc.).  The array itself
  # and each string are malloc-allocated; caller must free them.
  fun pam_getenvlist(pamh : PamHandle) : UInt8**
  # pam_set_item(3): set a PAM item (e.g. PAM_TTY) before pam_open_session
  # so pam_systemd registers the session on the correct seat/VT.
  PAM_TTY = 3
  fun pam_set_item(pamh : PamHandle, item_type : Int32, item : Void*) : Int32
  # pam_putenv(3): add a KEY=VALUE string to the PAM environment so
  # pam_systemd can read XDG_SESSION_TYPE, XDG_SEAT, XDG_VTNR, etc.
  fun pam_putenv(pamh : PamHandle, name_value : UInt8*) : Int32
end

# ═══════════════════════════════════════════════════════════════════════════════
# LibC extensions (not present in Crystal's stdlib)
# ═══════════════════════════════════════════════════════════════════════════════

lib LibC
  # Crystal's stdlib ships only getpwnam_r; we bind the simpler getpwnam
  # because this greeter is single-threaded and simplicity matters more.
  # LibC::Passwd is already defined by the stdlib (pulled in via io/console).
  fun getpwnam(name : Char*) : Passwd*

  # setuid is in stdlib unistd.cr; setgid is not — declare both for safety.
  fun setgid(gid : UInt32) : Int
  fun setuid(uid : UInt32) : Int

  # initgroups(3): initialise the supplementary group access list.
  # Must be called before setgid/setuid when dropping privileges.
  fun initgroups(user : Char*, group : UInt32) : Int

  # strdup(3): heap-copy a C string.  PAM will free() the copy.
  fun strdup(s : Char*) : Char*

  # calloc(3): system allocator — must be used for any memory PAM will free().
  # Crystal's Pointer(T).malloc uses the Boehm GC allocator, which is
  # incompatible with libc free() and causes heap corruption.
  fun calloc(nmemb : SizeT, size : SizeT) : Void*

  # ttyname(3): return the path of the terminal attached to fd (e.g. "/dev/tty1").
  fun ttyname(fd : Int) : Char*

  # chown(2): change ownership of a file.  Called before privilege drop so the
  # user's session can open the virtual console that Xorg needs.
  fun chown(path : Char*, owner : UInt, group : UInt) : Int

  # tcflush(3): discard queued terminal I/O.
  # TCIFLUSH (0) discards data received but not yet read — used to clear any
  # stale keystrokes before presenting the login prompt.
  TCIFLUSH = 0
  fun tcflush(fd : Int, queue_selector : Int) : Int
end

# ═══════════════════════════════════════════════════════════════════════════════
# PAM conversation callback
# ═══════════════════════════════════════════════════════════════════════════════
#
# Defined with `fun` (C calling convention) so Crystal can produce a real
# C function pointer for it.  Inside a `fun` body all Crystal types and
# stdlib are available — including Box.
#
# On Linux-PAM, `msgs` is PamMessage** — msgs[i] is a PamMessage*.
# We allocate the response array with malloc; PAM takes ownership and
# will free() each resp string as well as the array itself.

fun pam_conversation(
  num_msg   : Int32,
  msgs      : LibPAM::PamMessage**,
  resps_out : LibPAM::PamResponse**,
  appdata   : Void*
) : Int32
  password = Box(String).unbox(appdata)
  # Allocate with the system calloc so PAM can safely free() this array.
  # Using Crystal's Pointer(T).malloc here would allocate via Boehm GC,
  # which is incompatible with the libc free() PAM calls on cleanup.
  resps = LibC.calloc(num_msg.to_u64, sizeof(LibPAM::PamResponse))
            .as(Pointer(LibPAM::PamResponse))

  num_msg.times do |i|
    r     = resps + i
    style = msgs[i].value.msg_style   # msgs[i] → PamMessage*, .value → PamMessage

    if style == LibPAM::PAM_PROMPT_ECHO_OFF || style == LibPAM::PAM_PROMPT_ECHO_ON
      # Supply the password.  strdup because PAM will free() this string.
      r.value.resp         = LibC.strdup(password)
      r.value.resp_retcode = 0
    else
      # Info/error message from PAM — no response needed.
      r.value.resp         = Pointer(UInt8).null
      r.value.resp_retcode = 0
    end
  end

  resps_out.value = resps
  LibPAM::PAM_SUCCESS
end

# ═══════════════════════════════════════════════════════════════════════════════
# Terminal helpers
# ═══════════════════════════════════════════════════════════════════════════════

# Read one line from stdin without echoing characters.
# The terminal is always restored before returning (even on error/signal).
def read_password : String
  STDOUT.print "Password: "
  STDOUT.flush

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
    STDOUT.puts   # emit the newline the hidden Enter key didn't echo
  end
end

# ═══════════════════════════════════════════════════════════════════════════════
# PAM authentication
# ═══════════════════════════════════════════════════════════════════════════════

# Authenticate username + password against the "login" PAM service.
# Returns the live PamHandle on success so the caller can open a session
# with it; returns nil on any failure (pam_end is called internally).
# The password is never written to disk or to any log.
def authenticate(username : String, password : String) : LibPAM::PamHandle?
  box = Box.box(password)

  conv             = LibPAM::PamConv.new
  conv.conv        = ->pam_conversation(Int32, Pointer(Pointer(LibPAM::PamMessage)), Pointer(Pointer(LibPAM::PamResponse)), Pointer(Void))
  conv.appdata_ptr = box

  pamh = uninitialized LibPAM::PamHandle
  ret  = LibPAM.pam_start("login", username, pointerof(conv), pointerof(pamh))
  unless ret == LibPAM::PAM_SUCCESS
    STDERR.puts "greeter: pam_start failed (#{ret})"
    return nil
  end

  # Step 1: verify the supplied credentials.
  ret = LibPAM.pam_authenticate(pamh, 0)
  unless ret == LibPAM::PAM_SUCCESS
    LibPAM.pam_end(pamh, ret)
    return nil
  end

  # Step 2: check the account is usable (not expired, not locked, etc.).
  ret = LibPAM.pam_acct_mgmt(pamh, 0)
  unless ret == LibPAM::PAM_SUCCESS
    LibPAM.pam_end(pamh, ret)
    return nil
  end

  # Return the live handle — caller must call pam_close_session + pam_end.
  pamh
end

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
    STDERR.puts "greeter: initgroups failed"
    return false
  end
  if LibC.setgid(pw.pw_gid) != 0
    STDERR.puts "greeter: setgid(#{pw.pw_gid}) failed"
    return false
  end
  if LibC.setuid(pw.pw_uid) != 0
    STDERR.puts "greeter: setuid(#{pw.pw_uid}) failed"
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

def launch_session(pw : LibC::Passwd, pamh : LibPAM::PamHandle)
  user  = String.new(pw.pw_name)
  home  = String.new(pw.pw_dir)
  shell = String.new(pw.pw_shell)

  # Build a PATH for the child session.
  # On NixOS, tools like uname/expr/hexdump may only exist in nix store paths
  # not exposed via /run/current-system/sw/bin.  Find coreutils and util-linux
  # directly in /nix/store so startx can locate them regardless of profile state.
  nix_extra = [] of String
  ["coreutils", "util-linux", "xinit"].each do |pkg|
    Dir.glob("/nix/store/*-#{pkg}-*/bin").each { |d| nix_extra << d }
  end

  base_dirs = [
    "#{home}/.local/bin",
    "#{home}/.nix-profile/bin",
    "/nix/var/nix/profiles/per-user/#{user}/bin",
    "/run/current-system/sw/bin",
    "/nix/var/nix/profiles/default/bin",
    "/run/wrappers/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
  ]
  greeter_path = (ENV["PATH"]? || "").split(":").reject(&.empty?)
  session_path = (greeter_path + nix_extra + base_dirs).uniq.join(":")

  # Resolve startx to an absolute path by searching session_path directly.
  # Process.find_executable uses the greeter's live PATH (minimal on a TTY/init),
  # so we search the extended session_path we built above instead.
  startx_cmd = session_path.split(":").map { |d| "#{d}/startx" }.find { |p| File.executable?(p) }
  if startx_cmd.nil?
    STDERR.puts "greeter: startx not found in session PATH: #{session_path}"
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    return
  end
  STDERR.puts "greeter: startx resolved to #{startx_cmd}"

  # Tell pam_systemd which TTY and seat/VT this session belongs to.
  # These must be set BEFORE pam_open_session so logind registers the
  # session as Active=yes on seat0/vt1.  Without this polkit refuses
  # reboot/shutdown with "interactive authentication required".
  tty_path_str = LibC.ttyname(STDIN.fd)
  tty_str = tty_path_str.null? ? "/dev/tty1" : String.new(tty_path_str)
  tty_str.to_unsafe.as(Void*).tap do |ptr|
    LibPAM.pam_set_item(pamh, LibPAM::PAM_TTY, ptr)
  end
  ["XDG_SESSION_TYPE=x11", "XDG_SESSION_CLASS=user",
   "XDG_SEAT=seat0", "XDG_VTNR=1"].each do |kv|
    LibPAM.pam_putenv(pamh, kv)
  end

  # Register the session with systemd-logind.  This creates /run/user/<uid>,
  # starts the user's systemd slice (and with it PipeWire/PulseAudio), and
  # sets up the PAM environment for the session.  Without this call there is
  # no audio because the audio server never starts.
  ret = LibPAM.pam_open_session(pamh, 0)
  if ret != LibPAM::PAM_SUCCESS
    STDERR.puts "greeter: pam_open_session failed (#{ret}) — audio may be unavailable"
  end

  # Collect environment variables written by PAM modules (pam_systemd in
  # particular sets XDG_SESSION_ID and DBUS_SESSION_BUS_ADDRESS which are
  # required for PipeWire / D-Bus to work in the session).
  pam_env = {} of String => String
  envlist = LibPAM.pam_getenvlist(pamh)
  unless envlist.null?
    i = 0
    while !(ptr = envlist[i]).null?
      pair = String.new(ptr)
      eq   = pair.index('=')
      pam_env[pair[0...eq]] = pair[(eq + 1)..] if eq
      i += 1
    end
  end

  # Minimal, clean environment for the X session.
  # clear_env: true ensures no root-owned variables leak into the session.
  # ENV tells ksh/loksh which rc file to source for interactive subshells
  # (terminal emulators inside the X session).
  env = {
    "HOME"              => home,
    "USER"              => user,
    "SHELL"             => shell,
    "LOGNAME"           => user,
    "PATH"              => session_path,
    "ENV"               => "#{home}/.kshrc",
    # Required by PipeWire / PulseAudio to locate their socket.
    # pam_open_session (via pam_systemd) creates this directory;
    # we set it explicitly so the child always has the right value.
    "XDG_RUNTIME_DIR"   => "/run/user/#{pw.pw_uid}",
    # Tells systemd-logind / D-Bus what kind of session this is.
    "XDG_SESSION_TYPE"  => "x11",
    "XDG_SESSION_CLASS" => "user",
    "XDG_SEAT"          => "seat0",
    "XDG_VTNR"          => "1",
  }

  # Merge PAM-supplied variables (e.g. XDG_SESSION_ID, DBUS_SESSION_BUS_ADDRESS
  # from pam_systemd) without overwriting the values we set explicitly above.
  pam_env.each { |k, v| env[k] ||= v }

  puts "Starting fvwm3 session for #{user}..."

  child = Process.fork do
    # ── child ──────────────────────────────────────────────────────────────
    # Give the user ownership of the current TTY before dropping privileges.
    # Xorg needs to open the virtual console (e.g. /dev/tty1) as the session
    # user; without this chown it gets EACCES ("permission denied cannot open
    # virtual console 1").  We still have root here, so the chown succeeds.
    tty_path = LibC.ttyname(STDIN.fd)
    unless tty_path.null?
      LibC.chown(tty_path, pw.pw_uid, pw.pw_gid)
    end

    unless drop_privileges(pw)
      STDERR.puts "greeter: privilege drop failed; session aborted"
      exit 1
    end

    # Change into the user's home directory so $PWD matches $HOME.
    # Without this the process inherits the greeter's cwd (typically /)
    # which breaks anything that relies on a sane working directory.
    Dir.cd(home)

    # Run the X session inside a systemd user scope so that logind tracks
    # the session cgroup and cleans up all child processes when X exits.
    # The login shell sources ~/.profile first (giving us the full HM PATH),
    # then exec's systemd-run which creates the scope and execs startx.
    # --scope   : transient scope unit (systemd-run stays in the PID chain
    #             so the parent's wait() still works correctly)
    # --collect : auto-remove the unit after it exits
    # Using `exec "$@"` with positional args avoids shell-injection risk.
    begin
      Process.exec(
        command:   shell,
        args:      ["-l", "-c", "exec \"$@\"", "--",
                   "systemd-run", "--user", "--scope", "--collect",
                   "--", startx_cmd, "fvwm3", "--", ":0", "vt1"],
        env:       env,
        clear_env: true
      )
    rescue ex
      STDERR.puts "greeter: exec failed: #{ex.message}"
      exit 1
    end
  end

  # ── parent — wait for the X session to exit ─────────────────────────────
  status = child.wait
  if status.success?
    puts "Session ended normally."
  else
    puts "Session exited (code #{status.exit_code})."
  end

  # Close the PAM session (tears down the systemd-logind session, stops user
  # services) then end the transaction.
  LibPAM.pam_close_session(pamh, 0)
  LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
end

# ═══════════════════════════════════════════════════════════════════════════════
# Stub menu actions (bonus)
# ═══════════════════════════════════════════════════════════════════════════════

def do_reboot
  puts "  [stub] reboot — would exec: systemctl reboot"
end

def do_shutdown
  puts "  [stub] shutdown — would exec: systemctl poweroff"
end

# ═══════════════════════════════════════════════════════════════════════════════
# Main greeter loop
# ═══════════════════════════════════════════════════════════════════════════════
#
# Ctrl+C returns to the login prompt instead of terminating the process.
# The terminal is never left in a broken state; other TTYs remain accessible
# for recovery in all error paths.

Signal::INT.trap { puts "\n[Ctrl+C — back to login]" }

puts "\n+-----------------------------+"
puts   "|  Crystal TTY Login Greeter  |"
puts   "+-----------------------------+"

loop do
  # ── flush stale input before prompting ────────────────────────────────────
  LibC.tcflush(STDIN.fd, LibC::TCIFLUSH)

  # ── username ──────────────────────────────────────────────────────────────
  STDOUT.print "\nlogin: "
  STDOUT.flush
  username = STDIN.gets(chomp: true)
  next if username.nil? || username.strip.empty?
  username = username.strip

  # ── password (echo disabled) ──────────────────────────────────────────────
  password = read_password
  next if password.empty?   # e.g. empty line or signal-interrupted read

  # ── authenticate via PAM ──────────────────────────────────────────────────
  pamh = authenticate(username, password)
  unless pamh
    puts "Login incorrect."
    sleep 2.seconds   # brief delay to slow brute-force attempts
    next
  end

  pw = find_user(username)
  unless pw
    STDERR.puts "greeter: no passwd entry for '#{username}'"
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    next
  end

  puts "Welcome, #{username}."

  # ── session menu ──────────────────────────────────────────────────────────
  puts "\n  1) Start fvwm3 session"
  puts   "  2) Exit greeter"
  puts   "  3) Reboot  [stub]"
  puts   "  4) Shutdown [stub]"
  STDOUT.print "\nChoice [1]: "
  STDOUT.flush

  choice = (STDIN.gets(chomp: true) || "").strip
  choice = "1" if choice.empty?

  case choice
  when "1"
    launch_session(pw, pamh)   # launch_session owns pamh; calls pam_close_session + pam_end
    puts "Returning to login prompt."
  when "2"
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    puts "Goodbye."
    exit 0
  when "3"
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    do_reboot
  when "4"
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    do_shutdown
  else
    LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
    puts "Unknown choice '#{choice}'; back to login."
  end
end
