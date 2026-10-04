require "spec"
require "../src/sessions"
require "../src/terminal"

private def alice : Account
  Account.new(name: "alice", uid: 1000_u32, gid: 100_u32, home: "/home/alice", shell: "/bin/sh")
end

describe SessionPlan do
  it "builds startx arguments for a VT and display" do
    SessionPlan.startx_args("/home/alice/.xsession", 4, 1)
      .should eq(["/home/alice/.xsession", "--", ":1", "vt4"])
  end

  it "splits a desktop Exec= value on spaces" do
    SessionPlan.exec_args("  sway  --unsupported-gpu ").should eq(["sway", "--unsupported-gpu"])
  end

  it "describes the graphical session in the environment" do
    env = SessionPlan.graphical_env(alice, "wayland", 1, "seat0")

    env["USER"].should eq("alice")
    env["XDG_SESSION_TYPE"].should eq("wayland")
    env["XDG_VTNR"].should eq("1")
    env["XDG_RUNTIME_DIR"].should eq(Platform.runtime_dir(1000_u32))
    env["PATH"].should start_with("/home/alice/.local/bin:")
  end

  it "lets greeter values win over the PAM environment" do
    merged = SessionPlan.with_pam_env({"USER" => "alice"}, {"USER" => "mallory", "XDG_SESSION_ID" => "7"})

    merged.should eq({"USER" => "alice", "XDG_SESSION_ID" => "7"})
  end

  it "gives ssh only a minimal environment" do
    SessionPlan.ssh_env(alice, "linux").keys.sort!.should eq(%w[HOME PATH SHELL TERM USER])
  end

  it "names log events after the session kind" do
    SessionPlan::Kind::X11.event_name.should eq("x11")
    SessionPlan::Kind::Moonlight.event_name.should eq("moonlight")
  end
end

describe "Sessions.parse_desktop_entry" do
  it "reads Name and Exec from the Desktop Entry group, dropping field codes" do
    content = <<-DESKTOP
      [Desktop Entry]
      Name=Sway
      Name[de]=Sway DE
      Exec=sway %U
      [Desktop Action Other]
      Name=Ignored
      DESKTOP

    session = Sessions.parse_desktop_entry(content, Sessions::SessionType::Wayland).should be_a(Sessions::DesktopSession)
    session.name.should eq("Sway")
    session.exec.should eq("sway")
    session.label.should eq("Sway (Wayland)")
  end

  it "ignores keys outside the Desktop Entry group" do
    content = "[Other]\nName=X\nExec=x\n"
    Sessions.parse_desktop_entry(content, Sessions::SessionType::X11).should be_nil
  end

  it "requires both Name and Exec" do
    Sessions.parse_desktop_entry("[Desktop Entry]\nName=Only\n", Sessions::SessionType::X11).should be_nil
  end
end

describe "Terminal.feed" do
  it "appends printable ASCII" do
    Terminal.feed("ab", Bytes.empty, 'c'.ord.to_u8).should eq({"abc", Bytes.empty})
  end

  it "assembles a multi-byte UTF-8 character" do
    text, pending = Terminal.feed("", Bytes.empty, 0xC3_u8)
    text.should eq("")
    pending.size.should eq(1)

    Terminal.feed(text, pending, 0xB1_u8).should eq({"ñ", Bytes.empty})
  end

  it "deletes a whole character on backspace" do
    Terminal.feed("añ", Bytes.empty, Terminal::DELETE).should eq({"a", Bytes.empty})
  end

  it "ignores control bytes" do
    Terminal.feed("a", Bytes.empty, 0x01_u8).should eq({"a", Bytes.empty})
  end

  it "drops an invalid sequence" do
    text, pending = {"a", Bytes.empty}
    4.times { text, pending = Terminal.feed(text, pending, 0xFF_u8) }
    {text, pending}.should eq({"a", Bytes.empty})
  end
end
