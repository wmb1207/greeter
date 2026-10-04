require "./libs"
require "./logger"
require "./failure"

module Pam
  # One PAM transaction: the handle plus the boxed conversation data
  # (the password) that the handle calls back into.
  #
  # This is the only code that calls pam_* on a handle.  `finish` is
  # idempotent.  After fork(2) parent and child each hold a copy and each
  # must finish its own.
  class Transaction
    @finished = false

    # Run pam_authenticate + pam_acct_mgmt.  `tty` is set as PAM_TTY first so
    # modules such as pam_securetty and pam_faillock see the login terminal.
    def self.authenticate(service : String, username : String, password : String, tty : String?) : Transaction | Failure
      box = Box.box(password)
      conv = LibPAM::PamConv.new
      conv.conv = ->pam_conversation(Int32, Pointer(Pointer(LibPAM::PamMessage)), Pointer(Pointer(LibPAM::PamResponse)), Pointer(Void))
      conv.appdata_ptr = box
      handle = uninitialized LibPAM::PamHandle
      ret = LibPAM.pam_start(service, username, pointerof(conv), pointerof(handle))
      unless ret == LibPAM::PAM_SUCCESS
        Logger.error("auth.pam_start_failed", "PAM transaction could not start", {username: username, pam_code: ret})
        return Failure.new("Login incorrect.")
      end

      tx = new(handle, box)
      tx.tty = tty if tty

      ret = LibPAM.pam_authenticate(handle, 0)
      unless ret == LibPAM::PAM_SUCCESS
        Logger.warn("auth.rejected", "PAM authentication rejected credentials", {username: username, pam_code: ret})
        tx.finish(ret)
        return Failure.new("Login incorrect.")
      end

      ret = LibPAM.pam_acct_mgmt(handle, 0)
      unless ret == LibPAM::PAM_SUCCESS
        Logger.warn("auth.account_rejected", "PAM account check rejected user", {username: username, pam_code: ret})
        tx.finish(ret)
        return Failure.new("Login incorrect.")
      end

      tx
    end

    # `conv_data` is never read here; holding it keeps the boxed password
    # reachable for as long as PAM may call pam_conversation with it.
    private def initialize(@handle : LibPAM::PamHandle, @conv_data : Void*)
    end

    # PAM copies the string, so a temporary is fine.
    def tty=(path : String) : Nil
      LibPAM.pam_set_item(@handle, LibPAM::PAM_TTY, path.to_unsafe.as(Void*))
    end

    def putenv(name : String, value : String) : Nil
      LibPAM.pam_putenv(@handle, "#{name}=#{value}")
    end

    # Establish credentials and open the session; returns the PAM status.
    # On failure the credentials are already deleted.
    def open_session : Int32
      ret = LibPAM.pam_setcred(@handle, LibPAM::PAM_ESTABLISH_CRED)
      return ret unless ret == LibPAM::PAM_SUCCESS

      ret = LibPAM.pam_open_session(@handle, 0)
      LibPAM.pam_setcred(@handle, LibPAM::PAM_DELETE_CRED) unless ret == LibPAM::PAM_SUCCESS
      ret
    end

    # Close the session (tears down the logind session, stops user services)
    # and drop the credentials established by `open_session`.
    def close_session : Nil
      LibPAM.pam_close_session(@handle, 0)
      LibPAM.pam_setcred(@handle, LibPAM::PAM_DELETE_CRED)
    end

    # The PAM environment (e.g. XDG_SESSION_ID from pam_systemd).
    def env : Hash(String, String)
      list = LibPAM.pam_getenvlist(@handle)
      return {} of String => String if list.null?

      # The array and every string are malloc-allocated; we own and free them.
      env = {} of String => String
      i = 0
      while !(ptr = list[i]).null?
        name, separator, value = String.new(ptr).partition('=')
        env[name] = value unless separator.empty? || name.empty?
        LibC.free(ptr.as(Void*))
        i += 1
      end
      LibC.free(list.as(Void*))
      env
    end

    def finish(status : Int32 = LibPAM::PAM_SUCCESS) : Nil
      return if @finished
      @finished = true
      LibPAM.pam_end(@handle, status)
    end
  end
end
