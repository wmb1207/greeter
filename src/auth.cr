require "./result"
require "./libs"
require "./logger"
require "./account"

module Auth
  struct LoginSession
    getter username : String
    getter account : Account
    getter pamh : LibPAM::PamHandle
    # Keeps the conversation's appdata (the boxed password) reachable for as
    # long as this handle may still call back into pam_conversation, e.g. a
    # module prompting during pam_open_session.  Never read directly.
    @conv_data : Void*

    def initialize(@username : String, @account : Account, @pamh : LibPAM::PamHandle, @conv_data : Void*)
    end
  end

  struct Credentials
    getter username : String
    getter password : String

    def initialize(@username : String, @password : String)
    end
  end

  alias LoginSessionResult = Result(LoginSession)

  # `tty` is set as PAM_TTY before authentication so modules such as
  # pam_securetty and pam_faillock see the terminal the login came from.
  def self.auth(creds : Credentials, tty : String?) : LoginSessionResult
    started = do_auth(creds.username, creds.password, tty)
    return LoginSessionResult.error("Login incorrect.") unless started
    pamh, conv_data = started

    account = Account.find(creds.username)
    unless account
      Logger.error("auth.passwd_entry_missing", "Authenticated user has no passwd entry", {username: creds.username})
      LibPAM.pam_end(pamh, LibPAM::PAM_SUCCESS)
      return LoginSessionResult.error("Greeter: No passwd entry for '#{creds.username}'")
    end

    Logger.info("auth.succeeded", "Authentication succeeded", {username: creds.username, uid: account.uid})

    LoginSessionResult.ok(LoginSession.new(
      username: creds.username,
      account: account,
      pamh: pamh,
      conv_data: conv_data
    ))
  end

  # ═══════════════════════════════════════════════════════════════════════════════
  # PAM authentication
  # ═══════════════════════════════════════════════════════════════════════════════
  # Authenticate username + password against the "login" PAM service.
  # Returns the live PamHandle plus the boxed conversation data on success so
  # the caller can open a session with it; returns nil on any failure
  # (pam_end is called internally).
  # The password is never written to disk or to any log.
  private def self.do_auth(username : String, password : String, tty : String?) : {LibPAM::PamHandle, Void*}?
    box = Box.box(password)
    conv = LibPAM::PamConv.new
    conv.conv = ->pam_conversation(Int32, Pointer(Pointer(LibPAM::PamMessage)), Pointer(Pointer(LibPAM::PamResponse)), Pointer(Void))
    conv.appdata_ptr = box
    pamh = uninitialized LibPAM::PamHandle
    ret = LibPAM.pam_start("login", username, pointerof(conv), pointerof(pamh))
    unless ret == LibPAM::PAM_SUCCESS
      Logger.error("auth.pam_start_failed", "PAM transaction could not start", {username: username, pam_code: ret})
      return nil
    end

    LibPAM.pam_set_item(pamh, LibPAM::PAM_TTY, tty.to_unsafe.as(Void*)) if tty

    # Step 1: verify the supplied credentials.
    ret = LibPAM.pam_authenticate(pamh, 0)
    unless ret == LibPAM::PAM_SUCCESS
      Logger.warn("auth.rejected", "PAM authentication rejected credentials", {username: username, pam_code: ret})
      LibPAM.pam_end(pamh, ret)
      return nil
    end

    # Step 2: check the account is usable (not expired, not locked, etc.).
    ret = LibPAM.pam_acct_mgmt(pamh, 0)
    unless ret == LibPAM::PAM_SUCCESS
      Logger.warn("auth.account_rejected", "PAM account check rejected user", {username: username, pam_code: ret})
      LibPAM.pam_end(pamh, ret)
      return nil
    end

    # Return the live handle — caller must open/close the session and pam_end.
    {pamh, box}
  end
end
