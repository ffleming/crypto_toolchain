# encoding: ASCII-8BIT

require "base64"
require "pry-byebug"
require "pp"
require "uri"
require 'json'
require 'securerandom'
require "crypto_toolchain/version"
require "crypto_toolchain/extensions"
require "crypto_toolchain/utilities"
require "crypto_toolchain/tools"
require "crypto_toolchain/black_boxes"
require "crypto_toolchain/diffie_hellman"
require "crypto_toolchain/srp"

module CryptoToolchain
  AES_BLOCK_SIZE = 16
  PRINTABLE_CHARACTERS = ((0x20..0x7e).to_a + [0x0a, 0x0d]).map(&:chr).freeze
  NIST_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
  NIST_G = 2
  ASN1 = {
    md5:    "0 0\f\x06\b*\x86H\x86\xF7\r\x02\x05\x05\x00\x04\x10",
    sha1:   "0!0\t\x06\x05+\x0E\x03\x02\x1A\x05\x00\x04\x14",
    sha256: "010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 ",
    sha384: "0A0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\x040",
    sha512: "0Q0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\x04@"
  }.freeze

end
