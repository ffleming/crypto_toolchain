require "crypto_toolchain/srp/framework"
require "crypto_toolchain/srp/client"
require "crypto_toolchain/srp/server"

module CryptoToolchain
  module SRP
    ShutdownSignal = Class.new(RuntimeError)

    DELIMITER = "|"
    DEBUG = false
  end
end
