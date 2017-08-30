# encoding: ASCII-8BIT
class Integer
  def to_bits(pack_arg = "L>")
    [self].pack(pack_arg).to_bits
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
