# encoding: ASCII-8BIT
class String
  # Not cryptographically secure
  def self.random_bytes(n)
    n.times.with_object("") do |_, memo|
      memo << random_byte
    end
  end

  # Obviously not cryptographically secure
  def self.random_byte
    (0..255).to_a.sample.chr
  end

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

  def decrypt_ecb(key: , blocksize: CryptoToolchain::AES_BLOCK_SIZE, cipher: 'AES-128')
    in_blocks(blocksize).each_with_object("") do |block, memo|
      dec = OpenSSL::Cipher.new("#{cipher}-ECB")
      dec.decrypt
      dec.key = key
      dec.padding = 0
      plain = dec.update(block) + dec.final
      memo << plain
    end.without_pkcs7_padding(blocksize)
  end

  def encrypt_ecb(key: , blocksize: CryptoToolchain::AES_BLOCK_SIZE, cipher: 'AES-128')
    self.pad_pkcs7(blocksize).in_blocks(blocksize).each_with_object("").with_index do |(block, memo), i|

      enc = OpenSSL::Cipher.new("#{cipher}-ECB")
      enc.encrypt
      enc.key = key
      enc.padding = 0
      plain = enc.update(block) + enc.final

      memo << plain
    end
  end

  def decrypt_cbc(key: , iv: , blocksize: CryptoToolchain::AES_BLOCK_SIZE, cipher: 'AES-128', strip_padding: true)
    _blocks = in_blocks(blocksize)
    decrypted = _blocks.each_with_object("").with_index do |(block, memo), i|
      dec = OpenSSL::Cipher.new("#{cipher}-ECB")
      dec.decrypt
      dec.key = key
      dec.padding = 0
      unciphered = dec.update(block) + dec.final
      chain_block = i == 0 ? iv : _blocks[i - 1]
      memo << (unciphered ^ chain_block)
    end
    if strip_padding
      decrypted.without_pkcs7_padding(blocksize)
    else
      decrypted
    end
  end

  def encrypt_cbc(key: , iv: , blocksize: CryptoToolchain::AES_BLOCK_SIZE, cipher: 'AES-128')
    _blocks = pad_pkcs7(blocksize).in_blocks(blocksize)
    _blocks.each_with_object("").with_index do |(block, memo), i|
      chain_block = i == 0 ? iv : memo[(blocksize * -1)..-1]
      intermediate = block ^ chain_block
      enc = OpenSSL::Cipher.new("#{cipher}-ECB")
      enc.encrypt
      enc.key = key
      enc.padding = 0
      crypted = enc.update(intermediate) + enc.final
      memo << crypted
    end
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

  def encrypt_ctr(key: , nonce: , cipher: 'AES-128', start_counter: 0)
    each_byte.with_index(start_counter).with_object("") do |(byte, i), memo|
      ctr = i / 16
      ctr_params = [nonce, ctr].pack("Q<Q<")
      enc = OpenSSL::Cipher.new("#{cipher}-ECB")
      enc.encrypt
      enc.key = key
      enc.padding = 0
      keystream = enc.update(ctr_params) + enc.final
      memo << (byte.chr ^ keystream[i % 16])
    end
  end
  alias_method :decrypt_ctr, :encrypt_ctr

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

  def is_block_pkcs7_padded?(blocksize = CryptoToolchain::AES_BLOCK_SIZE)
    return true if self == blocksize.chr * blocksize
    (1...blocksize).each do |padding|
      return true if self[(blocksize - padding)..-1] == padding.chr * padding
    end
    false
  end

  def normalized_hamming_distance(blocks)
    raise ArgumentError.new("arg should be an array") unless blocks.is_a?(Array)
    (
      blocks[0].hamming_distance(blocks[1]) +
      blocks[0].hamming_distance(blocks[2]) +
      blocks[0].hamming_distance(blocks[3])
    ) / 3.0
  end
end
