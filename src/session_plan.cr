require "./account"
require "./platform"

# Pure description of a session: what to exec, with which environment, on
# which terminal.  Nothing here touches process state; Supervisor carries a
# Launch out.
module SessionPlan
  enum Kind
    X11
    Wayland
    Ssh
    Moonlight

    # Name used in log events ("session.<name>.ended").
    def event_name : String
      to_s.downcase
    end
  end

  # How the session registers with PAM/logind.
  record PamSession, tty : String, session_type : String, seat : String, vt : Int32

  record Launch,
    kind : Kind,
    account : Account,
    command : String,
    args : Array(String),
    env : Hash(String, String),
    # Terminal handed to the user for the session and given back to root
    # afterwards; nil leaves the greeter's terminal alone.
    tty : String?,
    # nil: no PAM session is opened (ssh only authenticates).
    pam : PamSession?,
    # What the user picked (session command or host), for logs.
    target : String

  def self.graphical_env(account : Account, session_type : String, vt : Int32, seat : String) : Hash(String, String)
    {
      "HOME"    => account.home,
      "USER"    => account.name,
      "SHELL"   => account.shell,
      "LOGNAME" => account.name,
      "PATH"    => session_path(account),
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
  end

  def self.moonlight_env(account : Account, vt : Int32, seat : String) : Hash(String, String)
    {
      "HOME"             => account.home,
      "USER"             => account.name,
      "SHELL"            => account.shell,
      "LOGNAME"          => account.name,
      "PATH"             => session_path(account),
      "XDG_RUNTIME_DIR"  => Platform.runtime_dir(account.uid),
      "XDG_SESSION_TYPE" => "x11",
      "XDG_SEAT"         => seat,
      "XDG_VTNR"         => vt.to_s,
      # Tell SDL2 to render directly to the KMS/DRM framebuffer — no X needed.
      "SDL_VIDEODRIVER" => "kmsdrm",
    }
  end

  def self.ssh_env(account : Account, term : String) : Hash(String, String)
    {
      "HOME"  => account.home,
      "USER"  => account.name,
      "SHELL" => account.shell,
      "PATH"  => session_path(account),
      "TERM"  => term,
    }
  end

  # Values set by the greeter win over the PAM environment.
  def self.with_pam_env(env : Hash(String, String), pam_env : Hash(String, String)) : Hash(String, String)
    pam_env.merge(env)
  end

  def self.session_path(account : Account) : String
    Platform.session_path(account.home, account.name)
  end

  # Desktop-file Exec= values are split on spaces (no shell, no quoting).
  def self.exec_args(exec : String) : Array(String)
    exec.split(' ', remove_empty: true)
  end

  def self.startx_args(client : String, vt : Int32, display : Int32) : Array(String)
    exec_args(client) + ["--", ":#{display}", "vt#{vt}"]
  end
end
