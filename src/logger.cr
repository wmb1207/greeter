require "json"

module Logger
  @@sink : IO = STDERR

  def self.sink=(sink : IO)
    @@sink = sink
  end

  def self.reset_sink
    @@sink = STDERR
  end

  def self.debug(event : String, message : String, fields : NamedTuple = NamedTuple.new)
    write("debug", event, message, fields)
  end

  def self.info(event : String, message : String, fields : NamedTuple = NamedTuple.new)
    write("info", event, message, fields)
  end

  def self.warn(event : String, message : String, fields : NamedTuple = NamedTuple.new)
    write("warn", event, message, fields)
  end

  def self.error(event : String, message : String, fields : NamedTuple = NamedTuple.new)
    write("error", event, message, fields)
  end

  private def self.write(level : String, event : String, message : String, fields : NamedTuple)
    record = JSON.build do |json|
      json.object do
        json.field "timestamp", Time.utc.to_rfc3339(fraction_digits: 3)
        json.field "level", level
        json.field "event", event
        json.field "message", message
        json.field "fields" do
          json.object do
            fields.each do |key, value|
              json.field key.to_s, value
            end
          end
        end
      end
    end

    @@sink << record << '\n'
    @@sink.flush
  rescue
    # Logging must not interrupt authentication or session cleanup.
  end
end
