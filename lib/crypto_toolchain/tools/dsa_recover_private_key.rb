module CryptoToolchain
  module Tools
    class DSARecoverPrivateKey
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

      def execute(min: 1, max: 0xffffffff)
        #     (s * k) - H(msg)
        # x = ----------------  mod q
        #             r
        (min..max).each do |k|
          numerator = ((s * k) - CryptoToolchain::Utilities::SHA1.digest(message).to_number) % q
          denominator = r.invmod(q)
          x = (numerator * denominator) % q
          kp = CryptoToolchain::BlackBoxes::DSAKeypair.new(p: p, q: q, g: g, private_key: x)
          return x.to_bin_string if kp.public_key == public_key
        end
        raise RuntimeError.new("Could not recover key")
      end
    end
  end
end
