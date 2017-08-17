# encoding: ASCII-8BIT
module CryptoToolchain
  module BlackBoxes
    class EcbInterpolateChosenPlaintextOracle
      MYSTERY_TEXT = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

      def initialize(key: String.random_bytes(16))
        @key = key
      end

      def encrypt(plaintext)
        obfuscate(plaintext).encrypt_ecb(key: key, blocksize: 16)
      end

      private

      attr_reader :key

      def obfuscate(str)
        "#{prefix}#{str}#{MYSTERY_TEXT.from_base64}"
      end

      def prefix
        @prefix ||= String.random_bytes(rand(1..64))
      end
    end
  end
end
