module CryptoToolchain
  module Tools
    class MT19937StreamCipherSeedRecoverer
      MAX_SEED = 0x0000ffff
      def initialize(ciphertext: , known: )
        @ciphertext = ciphertext
        @known = known
      end

      def execute
        (0..MAX_SEED).each do |seed|
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
