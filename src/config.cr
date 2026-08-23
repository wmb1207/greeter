require "yaml"
require "./logger"
require "./platform"

CONFIG_PATH = "/etc/greeter.conf"

enum MenuAction
  Exit
  Reboot
  Shutdown
  SSH
  Moonlight
end

record MenuEntry, action : MenuAction, label : String, host : String? = nil

struct Config
  getter title : String
  getter vt : Int32
  getter seat : String
  getter xsession_dirs : Array(String)
  getter wayland_session_dirs : Array(String)
  getter menu : Array(MenuEntry)

  def initialize(
    @title = "Greeter",
    @vt = 1,
    @seat = "seat0",
    @xsession_dirs = DEFAULT_XSESSION_DIRS.dup,
    @wayland_session_dirs = DEFAULT_WAYLAND_SESSION_DIRS.dup,
    @menu = DEFAULT_MENU.dup
  )
  end

  DEFAULT_XSESSION_DIRS = Platform.default_xsession_dirs
  DEFAULT_WAYLAND_SESSION_DIRS = Platform.default_wayland_session_dirs

  DEFAULT_MENU = [
    MenuEntry.new(MenuAction::Exit, "exit"),
    MenuEntry.new(MenuAction::Reboot, "reboot"),
    MenuEntry.new(MenuAction::Shutdown, "shutdown"),
    MenuEntry.new(MenuAction::SSH, "ssh"),
    MenuEntry.new(MenuAction::Moonlight, "moonlight desktop.wmb.arpa", "desktop.wmb.arpa"),
  ]

  def self.load(path : String = CONFIG_PATH) : Config
    return new unless File.exists?(path)
    parse(YAML.parse(File.read(path)))
  rescue ex
    Logger.error("config.load_failed", "Config error; using defaults", {path: path, error: ex.message})
    new
  end

  private def self.parse(doc : YAML::Any) : Config
    title = doc["title"]?.try(&.as_s) || "Greeter"
    vt    = doc["vt"]?.try(&.as_i) || 1
    seat  = doc["seat"]?.try(&.as_s) || "seat0"

    xsession_dirs = doc["xsession_dirs"]?.try(&.as_a.map(&.as_s)) || DEFAULT_XSESSION_DIRS.dup
    wayland_session_dirs = doc["wayland_session_dirs"]?.try(&.as_a.map(&.as_s)) || DEFAULT_WAYLAND_SESSION_DIRS.dup

    menu = doc["menu"]?.try(&.as_a.compact_map { |e| parse_menu_entry(e) }) || DEFAULT_MENU.dup

    new(title: title, vt: vt, seat: seat, xsession_dirs: xsession_dirs, wayland_session_dirs: wayland_session_dirs, menu: menu)
  end

  private def self.parse_menu_entry(entry : YAML::Any) : MenuEntry?
    action_str = entry["action"]?.try(&.as_s) || return nil
    action = case action_str.downcase
    when "exit"      then MenuAction::Exit
    when "reboot"    then MenuAction::Reboot
    when "shutdown"  then MenuAction::Shutdown
    when "ssh"       then MenuAction::SSH
    when "moonlight" then MenuAction::Moonlight
    else
      Logger.warn("config.unknown_menu_action", "Ignoring unknown menu action", {action: action_str})
      return nil
    end

    host  = entry["host"]?.try(&.as_s)
    label = entry["label"]?.try(&.as_s) || default_label(action, host)

    MenuEntry.new(action, label, host)
  end

  private def self.default_label(action : MenuAction, host : String?) : String
    case action
    in .exit?      then "exit"
    in .reboot?    then "reboot"
    in .shutdown?  then "shutdown"
    in .ssh?       then "ssh"
    in .moonlight? then "moonlight #{host || "localhost"}"
    end
  end
end
