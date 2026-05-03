struct Result(T)
  getter value : T?
  getter error : String?

  def initialize(@value : T?, error : String?)
  end

  def is_ok?
    !error
  end

  def self.ok(value : T) : Result
    new(value: value, error: nil)
  end

  def self.error(error : String) : Result
    new(value: nil, error: error)
  end
end
