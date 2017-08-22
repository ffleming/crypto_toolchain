# encoding: ASCII-8BIT

class String
  # Not cryptographically secure
  def self.random_bytes(n)
    n.times.with_object("") do |_, memo|
      memo << random_byte
    end
  end

  # Not cryptographically secure
  def self.random_byte
    (0..255).to_a.sample.chr
  end

  def from_hex
    raise StandardError.new("Not hex") unless hex?
    [self].pack("H*")
  end

  def to_hex
    each_byte.with_object("") do |byte, ret|
      ret << byte.to_s(16).rjust(2, "0")
    end
  end

  def hex?
    self !~ /[^0-9a-f]/i
  end

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

  TRIGRAM = %w(the ing and her ere ent tha nth was eth for dth).freeze
  DIGRAM = %w(th he in er an re ed  on es st en at to nt
              ha nd ou ea ng as or ti is et ar te se hi of).freeze
  def gram_score
    _score = 0
    (TRIGRAM + DIGRAM).each do |gram|
      _score += scan(/#{gram}/).length
    end
  end

  def in_blocks(num)
    bytes.map(&:chr).each_slice(num).map(&:join) || [""]
  end

  def repeat_to(len)
    ljust(len, self)
  end

  def hamming_distance(other)
    (self ^ other).to_bits.count("1")
  end

  def to_bits
    bytes.map {|b| format("%08d", b.to_s(2)) }.join
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
  def unique_blocks(blocksize)
    in_blocks(blocksize).each_with_object({}) do |block, found|
      found[block] ||= true
    end.keys
  end

  def pad_pkcs7(blocksize)
    _blocks = in_blocks(blocksize)
    pad_num = blocksize - _blocks.last.bytesize
    if pad_num == 0
      "#{self}#{blocksize.chr * blocksize}"
    else
      "#{self}#{pad_num.chr * pad_num}"
    end
  end

  def is_pkcs7_padded?(blocksize)
    # if self.size != blocksize
      return in_blocks(blocksize).last.is_block_pkcs7_padded?(blocksize)
    # end
  end

  def without_pkcs7_padding(blocksize, raise_error: false)
    if !is_pkcs7_padded?(blocksize)
      raise ArgumentError.new("Not PKCS7 padded") unless is_pkcs7_padded?(blocksize) if raise_error
      return self
    end
    self[0..(bytesize - (1 + bytes.last))]
  end

  def decrypt_ecb(key: , blocksize: , cipher: 'AES-128')
    in_blocks(blocksize).each_with_object("") do |block, memo|
      dec = OpenSSL::Cipher.new("#{cipher}-ECB")
      dec.decrypt
      dec.key = key
      dec.padding = 0
      plain = dec.update(block) + dec.final
      memo << plain
    end.without_pkcs7_padding(blocksize)
  end

  def encrypt_ecb(key: , blocksize: , cipher: 'AES-128')
    self.pad_pkcs7(blocksize).in_blocks(blocksize).each_with_object("").with_index do |(block, memo), i|

      enc = OpenSSL::Cipher.new("#{cipher}-ECB")
      enc.encrypt
      enc.key = key
      enc.padding = 0
      plain = enc.update(block) + enc.final

      memo << plain
    end
  end

  def decrypt_cbc(key: , iv: , blocksize: , cipher: 'AES-128', strip_padding: true)
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

  def encrypt_cbc(key: , iv: , blocksize: , cipher: 'AES-128')
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

  def encrypt_ctr(key: , nonce: , blocksize: , cipher: 'AES-128')
    in_blocks(blocksize).map.with_index do |block, ctr|
      ctr_params = [nonce, ctr].pack("Q<Q<")
      enc = OpenSSL::Cipher.new("#{cipher}-ECB")
      enc.encrypt
      enc.key = key
      enc.padding = 0
      keystream = enc.update(ctr_params) + enc.final
      block ^ keystream[0...(block.size)]
    end.join
  end
  alias_method :decrypt_ctr, :encrypt_ctr

  def contains_duplicate_blocks?(blocksize)
    _blocks = in_blocks(blocksize)
    _blocks.length > _blocks.uniq.length
  end
  alias_method :is_ecb_encrypted?, :contains_duplicate_blocks?

  protected

  def is_block_pkcs7_padded?(blocksize)
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
