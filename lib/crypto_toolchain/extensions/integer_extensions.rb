# encoding: ASCII-8BIT
class Integer
  def to_bits(pack_arg = "L>")
    [self].pack(pack_arg).to_bits
  end

  def lrot(num)
    ((self << num) & 0xffffffff) |
      ((self & 0xffffffff) >> (32 - num))
  end

  def rrot(num)
    ((self & 0xffffffff) >> num) |
      ((self << (32 - num)) & 0xffffffff)
  end

  # Thanks Bruce Schneier
  def modexp(exponent, mod)
    raise ArgumentError.new("Exponent must be non-negative") if exponent < 0
    product = 1
    base = self % mod
    until exponent == 0
      if exponent & 0x01 == 1
        product = (product * base) % mod
      end
      exponent = exponent >> 1
      base = (base**2) % mod
    end
    product
  end
  alias_method :modpow, :modexp
end
