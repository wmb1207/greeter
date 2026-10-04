# A recoverable failure with a user-facing message.
#
# Fallible operations return `T | Failure` (or `Failure?` when there is no
# value) instead of a two-field result object, so a failure can never be
# mistaken for success and callers must handle both cases.
record Failure, message : String
