require "./result"
require "./keyboard_layout"

module Platform
  alias CommandResult = Result(Bool)
  alias MachineDetails = Array(Tuple(String, String))

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

  def self.loadkeys_command : String?
    [
      "/run/current-system/sw/bin/loadkeys",
      "/usr/bin/loadkeys",
      "/bin/loadkeys",
      "/usr/local/bin/loadkeys",
    ].find { |path| File::Info.executable?(path) }
  end

  def self.apply_keymap(layout : KeyboardLayout) : CommandResult
    command = loadkeys_command
    return CommandResult.error("loadkeys command not found") if command.nil?

    output = IO::Memory.new
    error = IO::Memory.new
    status = Process.run(command.not_nil!, [layout.keymap], output: output, error: error)
    return CommandResult.ok(true) if status.success?

    detail = error.to_s.strip
    detail = output.to_s.strip if detail.empty?
    detail = "exit status #{status.exit_code}" if detail.empty?
    CommandResult.error(detail)
  rescue ex
    CommandResult.error(ex.message || ex.class.name)
  end

  def self.machine_details : MachineDetails
    details = [] of Tuple(String, String)
    add_detail(details, "host", hostname)
    add_detail(details, "os", os_name)
    add_detail(details, "kernel", kernel_release)
    add_detail(details, "machine", machine_model)
    add_detail(details, "cpu", cpu_model)
    add_detail(details, "memory", memory_total)
    details.concat(disk_layout)
    details
  end

  private def self.add_detail(details : MachineDetails, label : String, value : String?)
    clean = value.try(&.strip)
    details << {label, clean} unless clean.nil? || clean.empty?
  end

  private def self.hostname : String?
    read_first_line("/proc/sys/kernel/hostname") || read_first_line("/etc/hostname") || run_command("hostname")
  end

  private def self.kernel_release : String?
    read_first_line("/proc/sys/kernel/osrelease") || run_command("uname", ["-r"])
  end

  private def self.os_name : String?
    read_os_release("PRETTY_NAME") || read_first_line("/etc/issue") || run_command("uname", ["-s"])
  end

  private def self.machine_model : String?
    vendor = read_first_line("/sys/class/dmi/id/sys_vendor")
    product = read_first_line("/sys/class/dmi/id/product_name")
    version = read_first_line("/sys/class/dmi/id/product_version")

    [vendor, product, version]
      .compact
      .reject { |part| part.empty? || part.downcase == "to be filled by o.e.m." }
      .uniq
      .join(" ")
      .presence || run_command("sysctl", ["-n", "hw.model"])
  end

  private def self.cpu_model : String?
    read_key_value("/proc/cpuinfo", "model name") || run_command("sysctl", ["-n", "hw.model"])
  end

  private def self.memory_total : String?
    meminfo = read_key_value("/proc/meminfo", "MemTotal")
    return format_kib(meminfo) unless meminfo.nil?

    physmem = run_command("sysctl", ["-n", "hw.physmem"])
    physmem.try { |bytes| format_bytes(bytes) }
  end

  private def self.disk_layout : MachineDetails
    command = lsblk_command
    return [] of Tuple(String, String) if command.nil?

    lines = run_command(command.not_nil!, ["-o", "NAME,SIZE,TYPE,MOUNTPOINTS", "-n"]).try(&.lines.map(&.strip).reject(&.empty?)) || [] of String
    return [] of Tuple(String, String) if lines.empty?

    lines.first(8).map_with_index do |line, i|
      label = i == 0 ? "disks" : ""
      {label, line.gsub(/\s+/, " ")}
    end
  end

  private def self.lsblk_command : String?
    [
      "/run/current-system/sw/bin/lsblk",
      "/usr/bin/lsblk",
      "/bin/lsblk",
      "/usr/local/bin/lsblk",
    ].find { |path| File::Info.executable?(path) }
  end

  private def self.read_os_release(key : String) : String?
    return nil unless File.exists?("/etc/os-release")

    File.each_line("/etc/os-release") do |line|
      name, value = line.split("=", 2)
      return unquote(value) if name == key && !value.nil?
    end
  rescue
    nil
  end

  private def self.read_key_value(path : String, key : String) : String?
    return nil unless File.exists?(path)

    File.each_line(path) do |line|
      name, value = line.split(":", 2)
      return value.strip if name.strip == key && !value.nil?
    end
  rescue
    nil
  end

  private def self.read_first_line(path : String) : String?
    return nil unless File.exists?(path)

    File.read_lines(path).first?.try(&.strip)
  rescue
    nil
  end

  private def self.run_command(command : String, args = [] of String) : String?
    output = IO::Memory.new
    error = IO::Memory.new
    status = Process.run(command, args, output: output, error: error)
    status.success? ? output.to_s.strip : nil
  rescue
    nil
  end

  private def self.unquote(value : String) : String
    value.strip.gsub(/^"|"$/, "")
  end

  private def self.format_kib(value : String) : String?
    kib = value.split.first?.try(&.to_i64?)
    return nil if kib.nil?

    format_gib(kib * 1024)
  end

  private def self.format_bytes(value : String) : String?
    bytes = value.to_i64?
    return nil if bytes.nil?

    format_gib(bytes)
  end

  private def self.format_gib(bytes : Int64) : String
    gib = bytes / 1024_f64 / 1024_f64 / 1024_f64
    "#{gib.round(1)} GiB"
  end
end
