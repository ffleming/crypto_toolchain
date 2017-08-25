module CryptoToolchain
  module Tools
    class MT19937StreamCipherSeedRecoverer
      class << self
        def recover_from(ciphertext: , seed: )
          stream = CryptoToolchain::BlackBoxes::MT19937StreamCipher.new(ciphertext, seed: seed)
          stream.decrypt(ciphertext)
        end

        def valid_token?(tok, start: Time.now.to_i - 5, finish: Time.now.to_i)
          (start..finish).each do |seed|
            if tok == CryptoToolchain::BlackBoxes::MT19937StreamCipher.generate_token(seed: seed)
              return true
            end
          end
          false
        end
        alias_method :valid_token, :valid_token?
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
