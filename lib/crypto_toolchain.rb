require "base64"
require "pry-byebug"
require "pp"
require "uri"
require 'json'
require "crypto_toolchain/version"
require "crypto_toolchain/extensions"
require "crypto_toolchain/utilities"
require "crypto_toolchain/tools"
require "crypto_toolchain/black_boxes"

module CryptoToolchain
  AES_BLOCK_SIZE = 16
  PRINTABLE_CHARACTERS = ((0x20..0x7e).to_a + [0x0a, 0x0d]).map(&:chr).freeze
end
