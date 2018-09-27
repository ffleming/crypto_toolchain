# encoding: ASCII-8BIT

require "crypto_toolchain/extensions/string/padding"
require "crypto_toolchain/extensions/string/encryption"
require "crypto_toolchain/extensions/string/utilities"
require "crypto_toolchain/extensions/string/randomness"

class String
  include CryptoToolchain::Extensions::String::Padding
  include CryptoToolchain::Extensions::String::Encryption
  include CryptoToolchain::Extensions::String::Utilities
  extend CryptoToolchain::Extensions::String::Randomness
end
