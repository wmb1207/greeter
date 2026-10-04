require "spec"
require "../src/config"

describe Config do
  after_each do
    Logger.reset_sink
  end

  it "defaults the keyboard layout to us" do
    config = Config.load("/tmp/missing-greeter.conf")

    config.default_keyboard_layout.should eq(KeyboardLayout::US)
  end

  it "parses us as the default keyboard layout" do
    File.tempfile("greeter-config") do |file|
      file.print <<-YAML
      default_keyboard_layout: us
      YAML
      file.flush

      config = Config.load(file.path)

      config.default_keyboard_layout.should eq(KeyboardLayout::US)
    end
  end

  it "parses dvorak as the default keyboard layout" do
    File.tempfile("greeter-config") do |file|
      file.print <<-YAML
      default_keyboard_layout: dvorak
      YAML
      file.flush

      config = Config.load(file.path)

      config.default_keyboard_layout.should eq(KeyboardLayout::Dvorak)
    end
  end

  it "falls back to us for an invalid keyboard layout" do
    sink = IO::Memory.new
    Logger.sink = sink

    File.tempfile("greeter-config") do |file|
      file.print <<-YAML
      default_keyboard_layout: colemak
      YAML
      file.flush

      config = Config.load(file.path)

      config.default_keyboard_layout.should eq(KeyboardLayout::US)
      sink.to_s.should contain("config.invalid_keyboard_layout")
    end
  end
end

describe "Config vt" do
  after_each { Logger.reset_sink }

  it "falls back to vt 1 for an out-of-range vt" do
    sink = IO::Memory.new
    Logger.sink = sink

    File.tempfile("greeter-config") do |file|
      file.print "vt: 99\n"
      file.flush

      Config.load(file.path).vt.should eq(1)
      sink.to_s.should contain("config.invalid_vt")
    end
  end

  it "keeps a valid vt" do
    File.tempfile("greeter-config") do |file|
      file.print "vt: 2\n"
      file.flush

      Config.load(file.path).vt.should eq(2)
    end
  end
end
