require "signal"
require "io/console"


# ═══════════════════════════════════════════════════════════════════════════════
# LibPAM — FFI bindings for Linux-PAM
# ═══════════════════════════════════════════════════════════════════════════════
#
# Authentication happens in three steps:
#   1. pam_start       – open a transaction for the "login" service
#   2. pam_authenticate – verify credentials via the conversation callback
#   3. pam_acct_mgmt   – confirm the account is valid (not expired/locked)
#   4. pam_end         – release the transaction (always called)
#
# The conversation callback is how PAM asks the application for credentials.
# When PAM needs a password it calls our function with PAM_PROMPT_ECHO_OFF;
# we return whatever is in appdata_ptr.  We pass the password through
# appdata_ptr (a Box'd String) so no global state is needed.

@[Link("pam")]
lib LibPAM
  PAM_SUCCESS         =  0
  PAM_PROMPT_ECHO_OFF =  1   # silent prompt  → password
  PAM_PROMPT_ECHO_ON  =  2   # visible prompt → other credentials
  PAM_ERROR_MSG       =  3
  PAM_TEXT_INFO       =  4

  # One message PAM sends to the application (e.g. "Password: ").
  struct PamMessage
    msg_style : Int32
    msg       : UInt8*
  end

  # The application's reply to one PamMessage.
  # `resp` must be malloc-allocated; PAM (or pam_end) will free() it.
  struct PamResponse
    resp         : UInt8*
    resp_retcode : Int32    # unused by Linux-PAM, must be 0
  end

  # Passed to pam_start.  `conv` is our callback; `appdata_ptr` is
  # threaded through opaquely so the callback can reach application data.
  struct PamConv
    conv        : (Int32, PamMessage**, PamResponse**, Void*) -> Int32
    appdata_ptr : Void*
  end

  type PamHandle = Void*

  fun pam_start(service : UInt8*, user : UInt8*,
                conv : PamConv*, pamh : PamHandle*) : Int32
  fun pam_authenticate(pamh : PamHandle, flags : Int32) : Int32
  fun pam_acct_mgmt(pamh : PamHandle, flags : Int32) : Int32
  fun pam_open_session(pamh : PamHandle, flags : Int32) : Int32
  fun pam_close_session(pamh : PamHandle, flags : Int32) : Int32
  fun pam_end(pamh : PamHandle, status : Int32) : Int32
  fun pam_strerror(pamh : PamHandle, errnum : Int32) : UInt8*
  # Returns a null-terminated array of "KEY=VALUE" strings representing
  # all environment variables set by PAM modules (e.g. pam_systemd sets
  # XDG_SESSION_ID, DBUS_SESSION_BUS_ADDRESS, etc.).  The array itself
  # and each string are malloc-allocated; caller must free them.
  fun pam_getenvlist(pamh : PamHandle) : UInt8**
  # pam_set_item(3): set a PAM item (e.g. PAM_TTY) before pam_open_session
  # so pam_systemd registers the session on the correct seat/VT.
  PAM_TTY = 3
  fun pam_set_item(pamh : PamHandle, item_type : Int32, item : Void*) : Int32
  # pam_putenv(3): add a KEY=VALUE string to the PAM environment so
  # pam_systemd can read XDG_SESSION_TYPE, XDG_SEAT, XDG_VTNR, etc.
  fun pam_putenv(pamh : PamHandle, name_value : UInt8*) : Int32
end

# ═══════════════════════════════════════════════════════════════════════════════
# LibC extensions (not present in Crystal's stdlib)
# ═══════════════════════════════════════════════════════════════════════════════

lib LibC
  # Crystal's stdlib ships only getpwnam_r; we bind the simpler getpwnam
  # because this greeter is single-threaded and simplicity matters more.
  # LibC::Passwd is already defined by the stdlib (pulled in via io/console).
  fun getpwnam(name : Char*) : Passwd*

  # setuid is in stdlib unistd.cr; setgid is not — declare both for safety.
  fun setgid(gid : UInt32) : Int
  fun setuid(uid : UInt32) : Int

  # initgroups(3): initialise the supplementary group access list.
  # Must be called before setgid/setuid when dropping privileges.
  fun initgroups(user : Char*, group : UInt32) : Int

  # strdup(3): heap-copy a C string.  PAM will free() the copy.
  fun strdup(s : Char*) : Char*

  # calloc(3): system allocator — must be used for any memory PAM will free().
  # Crystal's Pointer(T).malloc uses the Boehm GC allocator, which is
  # incompatible with libc free() and causes heap corruption.
  fun calloc(nmemb : SizeT, size : SizeT) : Void*

  # ttyname(3): return the path of the terminal attached to fd (e.g. "/dev/tty1").
  fun ttyname(fd : Int) : Char*

  # chown(2): change ownership of a file.  Called before privilege drop so the
  # user's session can open the virtual console that Xorg needs.
  fun chown(path : Char*, owner : UInt, group : UInt) : Int

  # tcflush(3): discard queued terminal I/O.
  # TCIFLUSH discards data received but not yet read — used to clear any
  # stale keystrokes before presenting the login prompt.
  fun tcflush(fd : Int, queue_selector : Int) : Int

  # TIOCGWINSZ ioctl: query terminal window size.
  TIOCGWINSZ = 0x5413_u64

  struct Winsize
    ws_row    : UInt16
    ws_col    : UInt16
    ws_xpixel : UInt16
    ws_ypixel : UInt16
  end

  fun ioctl(fd : Int, request : ULong, ...) : Int

  # fork(2): create a child process.  Returns child PID in parent, 0 in
  # child, -1 on error.  Used instead of Process.fork (deprecated in 1.15+).
  fun fork : PidT

  # waitpid(2): wait for a specific child to change state.
  # options=0 blocks until the child exits.
  fun waitpid(pid : PidT, status : Int32*, options : Int32) : PidT
end

# ═══════════════════════════════════════════════════════════════════════════════
# PAM conversation callback
# ═══════════════════════════════════════════════════════════════════════════════
#
# Defined with `fun` (C calling convention) so Crystal can produce a real
# C function pointer for it.  Inside a `fun` body all Crystal types and
# stdlib are available — including Box.
#
# On Linux-PAM, `msgs` is PamMessage** — msgs[i] is a PamMessage*.
# We allocate the response array with malloc; PAM takes ownership and
# will free() each resp string as well as the array itself.

fun pam_conversation(
  num_msg   : Int32,
  msgs      : LibPAM::PamMessage**,
  resps_out : LibPAM::PamResponse**,
  appdata   : Void*
) : Int32
  password = Box(String).unbox(appdata)
  # Allocate with the system calloc so PAM can safely free() this array.
  # Using Crystal's Pointer(T).malloc here would allocate via Boehm GC,
  # which is incompatible with the libc free() PAM calls on cleanup.
  resps = LibC.calloc(num_msg.to_u64, sizeof(LibPAM::PamResponse))
            .as(Pointer(LibPAM::PamResponse))

  num_msg.times do |i|
    r     = resps + i
    style = msgs[i].value.msg_style   # msgs[i] → PamMessage*, .value → PamMessage

    if style == LibPAM::PAM_PROMPT_ECHO_OFF || style == LibPAM::PAM_PROMPT_ECHO_ON
      # Supply the password.  strdup because PAM will free() this string.
      r.value.resp         = LibC.strdup(password)
      r.value.resp_retcode = 0
    else
      # Info/error message from PAM — no response needed.
      r.value.resp         = Pointer(UInt8).null
      r.value.resp_retcode = 0
    end
  end

  resps_out.value = resps
  LibPAM::PAM_SUCCESS
end
