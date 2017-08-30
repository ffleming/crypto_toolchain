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
end
