# encoding: ASCII-8BIT

module CryptoToolchain
  module Extensions
    module String
      module Paddding
      end
    end
  end
end

module CryptoToolchain::Extensions::String::Padding
  def pad_pkcs7(blocksize = CryptoToolchain::AES_BLOCK_SIZE)
    _blocks = in_blocks(blocksize)
    pad_num = blocksize - _blocks.last.bytesize
    if pad_num == 0
      "#{self}#{blocksize.chr * blocksize}"
    else
      "#{self}#{pad_num.chr * pad_num}"
    end
  end

  def pad_pkcs1_5(bits)
    len = bits / 8
    if self.bytesize > len - 11
      raise ArgumentError.new("String #{self.inspect} is too long to pad with PKCS#1v1.5, length: #{self.bytesize}")
    end
    padstring = (len - 3 - self.bytesize).times.with_object("") { |_, memo| memo << rand(1..255).chr }
    "\x00\x02#{padstring}\x00#{self}"
  end

  def is_pkcs1_5_padded?(bits)
    self[0..1] == "\x00\x02"
  end

  def is_pkcs7_padded?(blocksize = CryptoToolchain::AES_BLOCK_SIZE)
    return in_blocks(blocksize).last.is_block_pkcs7_padded?(blocksize)
  end

  def without_pkcs7_padding(blocksize = CryptoToolchain::AES_BLOCK_SIZE, raise_error: false)
    if !is_pkcs7_padded?(blocksize)
      raise ArgumentError.new("Not PKCS7 padded") unless is_pkcs7_padded?(blocksize) if raise_error
      return self
    end
    self[0..(bytesize - (1 + bytes.last))]
  end

  protected

  def is_block_pkcs7_padded?(blocksize = CryptoToolchain::AES_BLOCK_SIZE)
    return true if self == blocksize.chr * blocksize
    (1...blocksize).each do |padding|
      return true if self[(blocksize - padding)..-1] == padding.chr * padding
    end
    false
  end

end
