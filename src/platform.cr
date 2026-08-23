module Platform
  def self.freebsd? : Bool
    {{ flag?(:freebsd) }}
  end

  def self.linux? : Bool
    {{ flag?(:linux) }}
  end

  def self.tty_path(vt : Int32) : String
    freebsd? ? "/dev/ttyv#{vt - 1}" : "/dev/tty#{vt}"
  end

  def self.term : String
    freebsd? ? "xterm" : "linux"
  end

  def self.default_xsession_dirs : Array(String)
    dirs = [
      "/usr/local/share/xsessions",
      "/usr/share/xsessions",
    ]
    dirs.concat([
      "/run/current-system/sw/share/xsessions",
    ]) if linux?
    dirs
  end

  def self.default_wayland_session_dirs : Array(String)
    dirs = [
      "/usr/local/share/wayland-sessions",
      "/usr/share/wayland-sessions",
    ]
    dirs.concat([
      "/run/current-system/sw/share/wayland-sessions",
    ]) if linux?
    dirs
  end

  def self.session_path(home : String, user : String = File.basename(home)) : String
    paths = [
      "#{home}/.local/bin",
      "#{home}/.nix-profile/bin",
      "/usr/local/bin",
      "/usr/local/sbin",
      "/usr/bin",
      "/usr/sbin",
      "/bin",
      "/sbin",
    ]

    if linux?
      paths.insert(2, "/nix/var/nix/profiles/per-user/#{user}/bin")
      paths.insert(3, "/run/current-system/sw/bin")
      paths.insert(4, "/nix/var/nix/profiles/default/bin")
      paths.insert(5, "/run/wrappers/bin")
    end

    paths.join(":")
  end

  def self.runtime_dir(uid : UInt32) : String
    freebsd? ? "/tmp/user-#{uid}" : "/run/user/#{uid}"
  end

  def self.ensure_runtime_dir(uid : UInt32, gid : UInt32) : Nil
    return unless freebsd?

    dir = runtime_dir(uid)
    Dir.mkdir_p(dir)
    LibC.chown(dir, uid, gid)
    File.chmod(dir, 0o700)
  end

  def self.reboot_command : Tuple(String, Array(String))
    freebsd? ? {"shutdown", ["-r", "now"]} : {"systemctl", ["reboot"]}
  end

  def self.shutdown_command : Tuple(String, Array(String))
    freebsd? ? {"shutdown", ["-p", "now"]} : {"systemctl", ["poweroff"]}
  end
end
