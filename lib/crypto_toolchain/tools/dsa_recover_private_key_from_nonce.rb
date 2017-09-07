module CryptoToolchain
  module Tools
    class DSARecoverPrivateKeyFromNonce
      def initialize(public_key: , message: , r: , s: , p: DSA_P, q: DSA_Q, g: DSA_G)
        @public_key = numberize(public_key)
        @p = p
        @q = q
        @g = g
        @r = numberize(r)
        @s = numberize(s)
        @message = message
      end

      attr_reader :public_key, :message, :r, :s, :p, :q, :g

      def valid_k?(k)
        x = private_key_from(k: k)
        kp = CryptoToolchain::BlackBoxes::DSAKeypair.new(p: p, q: q, g: g, private_key: x)
        kp.public_key == public_key
      end

      def private_key_from(k: )
        #     (s * k) - H(msg)
        # x = ----------------  mod q
        #             r
        numerator = ((s * k) - CryptoToolchain::Utilities::SHA1.digest(message).to_number) % q
        denominator = r.invmod(q)
        ((numerator * denominator) % q).to_bin_string
      end

      def execute(min: 1, max: 0xffffffff)
        (min..max).each do |k|
          return private_key_from(k: k) if valid_k?(k)
        end
        raise RuntimeError.new("Could not recover key")
      end
    end
  end
end
