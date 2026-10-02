module SessionTracker
  FIRST_VT = 3
  LAST_VT  = 7 # pool: vt3..vt7 (5 concurrent graphical sessions)

  struct Entry
    getter vt : Int32
    getter display : Int32
    getter username : String

    def initialize(@vt, @display, @username)
    end
  end

  # pid of the per-login X11 supervisor => the slot it occupies.
  @@table = {} of Int32 => Entry

  def self.next_vt : Int32?
    used = @@table.values.map(&.vt).to_set
    (FIRST_VT..LAST_VT).find { |v| !used.includes?(v) }
  end

  def self.add(pid : Int32, entry : Entry)
    @@table[pid] = entry
  end

  # Free the slots of supervisors that have exited.
  #
  # Crystal's runtime always owns SIGCHLD: it reaps every child with
  # waitpid(-1, WNOHANG) before any user handler runs, so calling waitpid
  # here would race it and lose exits (leaking slots).  Instead we let the
  # runtime reap and only ask whether the pid is still alive.  The supervisor
  # logs its own exit status before it terminates.
  def self.prune_finished : Nil
    @@table.reject! { |pid, _| !Process.exists?(pid) }
  end

  def self.capacity : Int32
    LAST_VT - FIRST_VT + 1
  end
end
