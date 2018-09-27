# encoding: ASCII-8BIT

module CryptoToolchain
  module Extensions
    module String
      module Encryption
      end
    end
  end
end

module CryptoToolchain::Extensions::String::Encryption
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

end
