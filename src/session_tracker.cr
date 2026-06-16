require "./libs"
require "./logger"

module SessionTracker
  FIRST_VT = 3
  LAST_VT  = 7  # pool: vt3..vt7 (5 concurrent graphical sessions)

  struct Entry
    getter vt       : Int32
    getter display  : Int32
    getter username : String
    getter pamh     : LibPAM::PamHandle

    def initialize(@vt, @display, @username, @pamh)
    end
  end

  @@table = {} of Int32 => Entry

  def self.next_vt : Int32?
    used = @@table.values.map(&.vt).to_set
    (FIRST_VT..LAST_VT).find { |v| !used.includes?(v) }
  end

  def self.add(pid : Int32, entry : Entry)
    @@table[pid] = entry
  end

  # Reap all finished children without blocking. Returns every (pid, entry)
  # pair that was in the table so callers can close the PAM session.
  def self.reap_all : Array({Int32, Entry})
    found = [] of {Int32, Entry}
    raw = 0_i32
    loop do
      pid = LibC.waitpid(-1, pointerof(raw), LibC::WNOHANG)
      break if pid <= 0
      if (e = @@table.delete(pid))
        found << {pid, e}
      end
    end
    found
  end

  def self.capacity : Int32
    LAST_VT - FIRST_VT + 1
  end

  def self.size : Int32
    @@table.size
  end
end
