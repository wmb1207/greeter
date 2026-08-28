enum KeyboardLayout
  US
  Dvorak

  def keymap : String
    case self
    in .us?
      "us"
    in .dvorak?
      "dvorak"
    end
  end

  def label : String
    keymap
  end

  def toggle : KeyboardLayout
    case self
    in .us?
      KeyboardLayout::Dvorak
    in .dvorak?
      KeyboardLayout::US
    end
  end

  def self.parse(value : String) : KeyboardLayout?
    case value.downcase
    when "us"
      KeyboardLayout::US
    when "dvorak"
      KeyboardLayout::Dvorak
    else
      nil
    end
  end
end
