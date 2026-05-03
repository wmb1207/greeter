require "./result"
require "./libs"

module Auth

  struct LoginSession
    getter username : String
    getter pw : LibC::Passwd
    getter pamh : LibPAM::PamHandle

    def initialize (@username : String, @pw : LibC::Passwd, @pamh : LibPAM::PamHandle)
    end
  end

  struct Credentials
    getter username : String
    getter password : String

    def initialize(@username : String, @password : String)
    end
  end

  alias LoginSessionResult = Result(LoginSession)
  def self.auth(creds : Credentials) : LoginSessionResult
    pamh = do_auth(creds.username, creds.password)
    return LoginSessionResult.error("Login incorrect.") unless pamh

    pw = find_user(creds.username)
    return LoginSessionResult.error("Greeter: No passwd entry for '#{creds.username}'") unless pw

    LoginSessionResult.ok(LoginSession.new(
                          username: creds.username,
                          pw: pw,
                          pamh: pamh
                        ))
  end

  # ═══════════════════════════════════════════════════════════════════════════════
  # PAM authentication
  # ═══════════════════════════════════════════════════════════════════════════════
  # Authenticate username + password against the "login" PAM service.
  # Returns the live PamHandle on success so the caller can open a session
  # with it; returns nil on any failure (pam_end is called internally).
  # The password is never written to disk or to any log.
  private def self.do_auth(username : String, password : String) : LibPAM::PamHandle?
    box = Box.box(password)
    conv             = LibPAM::PamConv.new
    conv.conv        = ->pam_conversation(Int32, Pointer(Pointer(LibPAM::PamMessage)), Pointer(Pointer(LibPAM::PamResponse)), Pointer(Void))
    conv.appdata_ptr = box
    pamh = uninitialized LibPAM::PamHandle
    ret  = LibPAM.pam_start("login", username, pointerof(conv), pointerof(pamh))
    unless ret == LibPAM::PAM_SUCCESS
      STDERR.puts "greeter: pam_start failed (#{ret})"
      return nil
    end

    # Step 1: verify the supplied credentials.
    ret = LibPAM.pam_authenticate(pamh, 0)
    unless ret == LibPAM::PAM_SUCCESS
      LibPAM.pam_end(pamh, ret)
      return nil
    end

    # Step 2: check the account is usable (not expired, not locked, etc.).
    ret = LibPAM.pam_acct_mgmt(pamh, 0)
    unless ret == LibPAM::PAM_SUCCESS
      LibPAM.pam_end(pamh, ret)
      return nil
    end

    # Return the live handle — caller must call pam_close_session + pam_end.
    pamh
  end

end
