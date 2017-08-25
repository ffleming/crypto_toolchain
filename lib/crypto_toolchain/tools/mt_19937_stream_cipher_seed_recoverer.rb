module CryptoToolchain
  module Tools
    class MT19937StreamCipherSeedRecoverer
      def self.recover_from(ciphertext: , seed: )
        stream = CryptoToolchain::BlackBoxes::MT19937StreamCipher.new(ciphertext, seed: seed)
        stream.decrypt(ciphertext)
      end

      def initialize(ciphertext: , known: )
        @ciphertext = ciphertext
        @known = known
      end

      def execute
        (0..CryptoToolchain::BlackBoxes::MT19937StreamCipher::MAX_SEED).each do |seed|
          cipher = CryptoToolchain::BlackBoxes::MT19937StreamCipher.new(ciphertext, seed: seed)
          if cipher.decrypt(ciphertext).include?(known)
            return seed
          end
        end
      end

      attr_reader :known, :ciphertext

    end
  end
end
