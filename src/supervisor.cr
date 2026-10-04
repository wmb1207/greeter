require "./account"
require "./libs"
require "./logger"
require "./pam"
require "./platform"
require "./session_plan"

# Runs a SessionPlan::Launch in a per-login supervisor process:
#
#   greeter ──fork──▶ supervisor: open PAM session, fork worker, wait,
#                     close PAM session, give the terminal back, log, _exit
#                         └──fork──▶ worker: chown tty, drop privileges, exec
#
# The PAM session is opened in the supervisor, not the long-lived greeter;
# otherwise logind ties the session to the greeter and later users do not
# get /run/user/<uid>.
module Supervisor
  # Fork the supervisor.  Returns its pid; the caller either waits on it or
  # tracks it.  The caller still finishes its own copy of `pam`.
  def self.start(launch : SessionPlan::Launch, pam : Pam::Transaction) : Int32 | Failure
    event = launch.kind.event_name
    Logger.info("session.#{event}.starting", "Starting session", log_fields(launch))

    pid = LibC.fork
    if pid == 0
      in_child("session.#{event}.supervisor_failed") { supervise(launch, pam) }
    elsif pid < 0
      Logger.error("session.#{event}.fork_failed", "Could not fork session supervisor", log_fields(launch))
      return Failure.new("Greeter: fork failed")
    end
    pid
  end

  # Block until `pid` exits.  Returns nil if it was already reaped elsewhere
  # (its status is then unknown).
  def self.wait(pid : Int32) : Process::Status?
    raw = 0_i32
    LibC.waitpid(pid, pointerof(raw), 0) == pid ? Process::Status.new(raw) : nil
  end

  # A forked child must never return into the greeter: it would run a second
  # greeter loop on the same TTY (as root if the privilege drop failed).  The
  # block is expected to exec or _exit; any exception or fall-through ends
  # the child with _exit, which also skips at_exit handlers and the flushing
  # of stdio buffers inherited from the parent.
  def self.in_child(event : String, &) : NoReturn
    yield
    Logger.error(event, "Session child returned without exec")
    LibC._exit(1)
  rescue ex
    Logger.error(event, "Session child failed", {error: ex.message})
    LibC._exit(1)
  end

  def self.log_end(event : String, status : Process::Status?, fields : NamedTuple) : Nil
    name = "session.#{event}.ended"
    if status.nil?
      Logger.warn(name, "Session ended with unknown status", fields)
    elsif (code = status.exit_code?) && code == 0
      Logger.info(name, "Session ended", fields.merge(exit_code: code))
    elsif code
      Logger.warn(name, "Session exited abnormally", fields.merge(exit_code: code))
    else
      Logger.warn(name, "Session terminated by signal", fields.merge(signal: status.exit_signal?.try(&.value)))
    end
  end

  # Order is mandatory: initgroups → setgid → setuid.  setuid must come last:
  # once a process drops to an unprivileged UID it can no longer alter its GID
  # or supplementary groups on Linux.
  def self.drop_privileges(account : Account) : Bool
    if LibC.initgroups(account.name, account.gid) != 0
      Logger.error("privileges.initgroups_failed", "Could not initialize supplementary groups", {uid: account.uid})
      return false
    end
    if LibC.setgid(account.gid) != 0
      Logger.error("privileges.setgid_failed", "Could not set process gid", {uid: account.uid, gid: account.gid})
      return false
    end
    if LibC.setuid(account.uid) != 0
      Logger.error("privileges.setuid_failed", "Could not set process uid", {uid: account.uid})
      return false
    end
    true
  end

  private def self.supervise(launch : SessionPlan::Launch, pam : Pam::Transaction) : NoReturn
    event = launch.kind.event_name
    env = launch.env

    if session = launch.pam
      ret = open_pam_session(pam, session)
      if ret != LibPAM::PAM_SUCCESS
        Logger.error("session.#{event}.pam_open_failed", "PAM session could not open", log_fields(launch).merge(pam_code: ret))
        pam.finish(ret)
        LibC._exit(1)
      end
      Logger.info("session.#{event}.pam_opened", "PAM session opened", log_fields(launch))
      env = SessionPlan.with_pam_env(env, pam.env)
    end

    pid = LibC.fork
    if pid == 0
      in_child("session.#{event}.exec_failed") do
        become_user(launch.account, launch.tty)
        Process.exec(command: launch.command, args: launch.args, env: env, clear_env: true)
      end
    elsif pid < 0
      Logger.error("session.#{event}.fork_failed", "Could not fork session worker", log_fields(launch))
      end_pam(launch, pam)
      LibC._exit(1)
    end

    status = wait(pid)
    end_pam(launch, pam)
    launch.tty.try { |tty| Platform.restore_tty(tty) }
    log_end(event, status, log_fields(launch).merge(pid: pid))
    LibC._exit(status.try(&.exit_code?) || 1)
  end

  # Tell pam_systemd which TTY and seat/VT this session belongs to.  These
  # must be set BEFORE pam_open_session so logind registers the session as
  # Active=yes on the correct seat/VT.
  private def self.open_pam_session(pam : Pam::Transaction, session : SessionPlan::PamSession) : Int32
    pam.tty = session.tty
    pam.putenv("XDG_SESSION_TYPE", session.session_type)
    pam.putenv("XDG_SESSION_CLASS", "user")
    pam.putenv("XDG_SEAT", session.seat)
    pam.putenv("XDG_VTNR", session.vt.to_s)
    pam.open_session
  end

  private def self.end_pam(launch : SessionPlan::Launch, pam : Pam::Transaction) : Nil
    pam.close_session if launch.pam
    pam.finish
  end

  # Worker-side setup before exec: hand the terminal to the user (given back
  # by the supervisor afterwards), then drop privileges.
  private def self.become_user(account : Account, tty : String?) : Nil
    LibC.chown(tty, account.uid, account.gid) if tty
    Platform.ensure_runtime_dir(account.uid, account.gid)
    LibC._exit(1) unless drop_privileges(account)
    Dir.cd(account.home)
  end

  private def self.log_fields(launch : SessionPlan::Launch)
    {username: launch.account.name, uid: launch.account.uid, target: launch.target}
  end
end
