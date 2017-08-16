# encoding: ASCII-8BIT
module CryptoToolchain
  module BlackBoxes
    class EcbPrependChosenPlaintextOracle
      MYSTERY_TEXT = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
      KEY = "\xC9P\xAF\b\xC3=\"\x84\x9AS\xB12\xC9*\xB0\x18".freeze

      def encrypt(plaintext)
        obfuscate(plaintext).encrypt_ecb(key: KEY, blocksize: 16)
      end

      private

      def obfuscate(str)
        "#{str}#{MYSTERY_TEXT.from_base64}"
      end
    end
  end
end
