require "spec"
require "../src/sessions"
require "../src/supervisor"

describe Account do
  it "copies the passwd entry of an existing user" do
    account = Account.find("root").should be_a(Account)

    account.name.should eq("root")
    account.uid.should eq(0)
    account.gid.should eq(0)
  end

  it "returns nil for an unknown user" do
    Account.find("no-such-greeter-user").should be_nil
  end
end

describe SessionTracker do
  it "frees the slot of a supervisor that has exited" do
    process = Process.new("true")
    SessionTracker.add(process.pid.to_i32, SessionTracker::Entry.new(SessionTracker::FIRST_VT, 0, "alice"))
    SessionTracker.next_vt.should eq(SessionTracker::FIRST_VT + 1)

    process.wait
    SessionTracker.prune_finished

    SessionTracker.next_vt.should eq(SessionTracker::FIRST_VT)
  end
end

describe Supervisor do
  after_each { Logger.reset_sink }

  it "logs a clean exit as info and a signal as warn" do
    sink = IO::Memory.new
    Logger.sink = sink

    Supervisor.log_end("x11", Process::Status.new(0), {username: "alice"})
    Supervisor.log_end("x11", Process::Status.new(Signal::KILL.value), {username: "alice"})
    Supervisor.log_end("ssh", nil, {username: "alice"})

    records = sink.to_s.lines.map { |line| JSON.parse(line) }
    records.map { |record| {record["event"].as_s, record["level"].as_s} }.should eq([
      {"session.x11.ended", "info"},
      {"session.x11.ended", "warn"},
      {"session.ssh.ended", "warn"},
    ])
    records[0]["fields"]["exit_code"].as_i.should eq(0)
    records[1]["fields"]["signal"].as_i.should eq(Signal::KILL.value)
  end

  it "ends a forked child that returns without exec instead of resuming the parent" do
    Logger.sink = IO::Memory.new
    pid = LibC.fork
    if pid == 0
      Supervisor.in_child("spec.child") { }
    end

    status = Supervisor.wait(pid).should be_a(Process::Status)
    status.exit_code.should eq(1)
  end
end
