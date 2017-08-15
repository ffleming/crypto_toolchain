module CryptoToolchain
  module Tools
    class EcbDetector
      def initialize(ciphertext, generator: , blocksize: )
        @ciphertext = ciphertext
        @blocksize = blocksize
      end

      def is_ecb_encrypted?

      end

    end
  end
end
