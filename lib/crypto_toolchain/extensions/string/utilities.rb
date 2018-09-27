# encoding: ASCII-8BIT

module CryptoToolchain
  module Extensions
    module String
      module Utilities
      end
    end
  end
end

module CryptoToolchain::Extensions::String::Utilities
  def from_hex
    raise StandardError.new("Not hex") unless hex?
    [self].pack("H*")
  end

  def to_hex
    unpack("H*").first
  end

  def hex?
    self !~ /[^0-9a-f]/i
  end

  def swap_endian
    raise ArgumentError.new("Bytesize must be multiple of 4") unless bytesize % 4 == 0
    unpack("L<*").pack("L>*")
  end

  alias_method :swap_endianness, :swap_endian

  def to_base64(strict: true)
    if strict
      Base64.strict_encode64(self)
    else
      Base64.encode64(self)
    end
  end

  def from_base64(strict: true)
    if strict
      begin
        Base64.strict_decode64(self)
      rescue ArgumentError
        Base64.decode64(self)
      end
    else
      Base64.decode64(self)
    end
  end

  def ^(other)
    if length != other.length
      raise ArgumentError.new("Must be same lengths, self: #{self.bytesize}, other: #{other.bytesize}")
    end
    each_byte.with_index.with_object("") do |(byte, i), ret|
      ret << (byte.ord ^ other[i].ord)
    end
  end

  def score
    scan(/[etaoin shrdlu]/i).size
  end

  def in_blocks(blocksize = CryptoToolchain::AES_BLOCK_SIZE)
    bytes.map(&:chr).each_slice(blocksize).map(&:join) || [""]
  end

  def repeat_to(len)
    ljust(len, self)
  end

  def to_number
    to_hex.to_i(16)
  end

  def hamming_distance(other)
    (self ^ other).to_bits.count("1")
  end

  def to_bits
    self.unpack("B*").first
  end
  alias_method :bitstring, :to_bits
  alias_method :bits, :to_bits

  def potential_repeating_xor_keysizes(take: 3, min: 2, max: 40)
    (min..max).sort_by do |size|
      normalized_hamming_distance(self.in_blocks(size)) / size.to_f
    end.take(take)
  end

  def potential_repeating_xor_keys(potential_keysizes: self.potential_repeating_xor_keysizes)
    potential_keysizes.map do |keysize|
      arr = self.in_blocks(keysize)
      transposed = (0...keysize).each_with_object([]) do |i, memo|
        memo << arr.map { |row| row[i] }.join
      end
      key = transposed.each_with_object("") do |str, memo|
        memo << CryptoToolchain::Tools.detect_single_character_xor(str)
      end
      key
    end
  end

  # unique blocks.  block size is in _bytes_
  def unique_blocks(blocksize = CryptoToolchain::AES_BLOCK_SIZE)
    in_blocks(blocksize).each_with_object({}) do |block, found|
      found[block] ||= true
    end.keys
  end

  # Bitstring is indexed as a normal string, ie:
  #
  # 'd' = 0x64 = 01100100
  #              01234567
  # 'd'.bitflip(7) => 'e'
  def bitflip(bit_index, byte_index: 0)
    byte_offset, bit_offset = bit_index.divmod(8)
    byte_offset += byte_index
    target = self.dup
    target[byte_offset] = (target[byte_offset].ord ^  (1 << (7-bit_offset))).chr
    target
  end
  alias_method :bit_flip, :bitflip
  alias_method :flipbit, :bitflip
  alias_method :flip_bit, :bitflip
  alias_method :flip, :bitflip

  def contains_duplicate_blocks?(blocksize = CryptoToolchain::AES_BLOCK_SIZE)
    _blocks = in_blocks(blocksize)
    _blocks.length > _blocks.uniq.length
  end
  alias_method :is_ecb_encrypted?, :contains_duplicate_blocks?

  # Thanks Ruby Facets!
  def snakecase
    gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2').
      gsub(/([a-z\d])([A-Z])/,'\1_\2').
      tr('-', '_').
      gsub(/\s/, '_').
      gsub(/__+/, '_').
      downcase
  end
  alias_method :snake_case, :snakecase
  alias_method :underscore, :snakecase

  protected

  def normalized_hamming_distance(blocks)
    raise ArgumentError.new("arg should be an array") unless blocks.is_a?(Array)
    (
      blocks[0].hamming_distance(blocks[1]) +
      blocks[0].hamming_distance(blocks[2]) +
      blocks[0].hamming_distance(blocks[3])
    ) / 3.0
  end
end
