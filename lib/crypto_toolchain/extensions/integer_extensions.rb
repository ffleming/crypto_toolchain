# encoding: ASCII-8BIT
class Integer
  def to_bits
    ensure_32_bit do
      (self & 0xffffffff).
        to_s(2).
        rjust(32, "0")
    end
  end

  def lrot(num)
    ensure_32_bit do
      ((self << num) & 0xffffffff) |
        (self >> (32 - num))
    end
  end

  def rrot(num)
    ensure_32_bit do
      (self >> num) |
        ((self << (32 - num)) & 0xffffffff)
    end
  end

  def ensure_32_bit
    raise ArgumentError.new("This only works for 32 bit numbers") unless bit_length <= 32
    yield if block_given?
  end
end
