require "./account"
require "./failure"
require "./logger"
require "./pam"

module Auth
  record Credentials, username : String, password : String

  # An authenticated user and the PAM transaction that vouches for them.
  record Login, account : Account, pam : Pam::Transaction

  # Authenticate and yield the login.  The transaction is always finished
  # when the block returns or raises; code that forks finishes its own copy.
  # Returns the failure when authentication does not succeed.
  def self.login(creds : Credentials, tty : String?, & : Login ->) : Failure?
    login = authenticate(creds, tty)
    return login if login.is_a?(Failure)

    begin
      yield login
    ensure
      login.pam.finish
    end
    nil
  end

  def self.authenticate(creds : Credentials, tty : String?) : Login | Failure
    pam = Pam::Transaction.authenticate("login", creds.username, creds.password, tty)
    return pam if pam.is_a?(Failure)

    account = Account.find(creds.username)
    if account.nil?
      Logger.error("auth.passwd_entry_missing", "Authenticated user has no passwd entry", {username: creds.username})
      pam.finish
      return Failure.new("Greeter: No passwd entry for '#{creds.username}'")
    end

    Logger.info("auth.succeeded", "Authentication succeeded", {username: account.name, uid: account.uid})
    Login.new(account, pam)
  end
end
