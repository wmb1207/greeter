require "spec"
require "json"
require "../src/logger"

class FailingIO < IO
  def read(slice : Bytes) : Int32
    0
  end

  def write(slice : Bytes) : Nil
    raise IO::Error.new("write failed")
  end
end

describe Logger do
  after_each do
    Logger.reset_sink
  end

  it "writes a JSONL record with nested typed fields" do
    sink = IO::Memory.new
    Logger.sink = sink

    Logger.info(
      "session.started",
      "Started \"desktop\"\ncleanly",
      {username: "alice", uid: 1000, active: true, load: 1.5, optional: nil}
    )

    lines = sink.to_s.lines
    lines.size.should eq(1)

    record = JSON.parse(lines.first)
    timestamp = record["timestamp"].as_s
    timestamp.should match(/\.\d{3}Z$/)
    Time.parse_rfc3339(timestamp)
    record["level"].as_s.should eq("info")
    record["event"].as_s.should eq("session.started")
    record["message"].as_s.should eq("Started \"desktop\"\ncleanly")
    record["fields"]["username"].as_s.should eq("alice")
    record["fields"]["uid"].as_i.should eq(1000)
    record["fields"]["active"].as_bool.should be_true
    record["fields"]["load"].as_f.should eq(1.5)
    record["fields"]["optional"].raw.should be_nil
  end

  it "supports each severity helper and emits one record per line" do
    sink = IO::Memory.new
    Logger.sink = sink

    Logger.debug("debug.event", "debug")
    Logger.info("info.event", "info")
    Logger.warn("warn.event", "warn")
    Logger.error("error.event", "error")

    records = sink.to_s.lines.map { |line| JSON.parse(line) }
    records.map { |record| record["level"].as_s }.should eq(%w[debug info warn error])
    records.map { |record| record["event"].as_s }.should eq(%w[debug.event info.event warn.event error.event])
  end

  it "does not propagate sink failures" do
    Logger.sink = FailingIO.new

    Logger.error("sink.failed", "This write is best effort")
  end
end
