require "system/user"

# Immutable snapshot of a passwd entry.
#
# Built from System::User, which copies every field into Crystal strings.
# Never hold LibC::Passwd from getpwnam(3): its char* fields point into libc's
# static buffer and are overwritten by the next getpw* call (including calls
# made inside PAM modules).
record Account, name : String, uid : UInt32, gid : UInt32, home : String, shell : String do
  def self.find(name : String) : Account?
    user = System::User.find_by?(name: name)
    return nil if user.nil?

    new(
      name: user.username,
      uid: user.id.to_u32,
      gid: user.group_id.to_u32,
      home: user.home_directory,
      shell: user.shell
    )
  end
end
