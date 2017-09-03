module CryptoToolchain
  module BlackBoxes
    class RSAKeypair
      PrivateKey = Struct.new(:d, :n)
      PublicKey = Struct.new(:e, :n)

      def initialize(bits: 32)
        @p = OpenSSL::BN::generate_prime(bits).to_i
        @q = OpenSSL::BN::generate_prime(bits).to_i
        @n = @p * @q
        et = (@p-1) * (@q-1)
        @e = 3
        @d = @e.invmod(et)
      end

      def encrypt(m, to: private_key)
        raise ArgumentError.new("Message should be a string") unless m.is_a?(String)
        m.
          to_hex.
          to_i(16).
          modpow(to.e, to.n).
          to_s(16)
      end

      def decrypt(m)
        raise ArgumentError.new("Message should be a string") unless m.is_a?(String)
        m.
          to_i(16).
          modpow(private_key.d, private_key.n).
          to_s(16).
          from_hex
      end

      def public_key
        @public_key ||= PublicKey.new(@e, @n)
      end
      alias_method :pubkey, :public_key

      def private_key
        @private_key ||= PrivateKey.new(@d, @n)
      end
      alias_method :privkey, :private_key
    end
  end
end
