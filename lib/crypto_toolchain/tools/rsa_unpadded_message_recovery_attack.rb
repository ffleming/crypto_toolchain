module CryptoToolchain
  module Tools
    class RSAUnpaddedMessageRecoveryAttack

      attr_reader :oracle, :s

      def initialize(oracle: , s: 2)
        @oracle = oracle
        @s = s
      end

      def execute(ciphertext)
        plaintext(
          p_prime(
            c_prime(
              ciphertext.to_number
            )
          )
        )
      end

      private

      def e
        oracle.keypair.e
      end

      def n
        oracle.keypair.public_key.n
      end

      def c_prime(c)
        (s.modpow(e, n) * c) % n
      end

      def p_prime(_c_prime)
        oracle.execute(
          _c_prime.to_bin_string
        ).to_number
      end

      def plaintext(_p_prime)
        ((_p_prime * s.invmod(n)) % n).to_bin_string
      end
    end
  end
end
