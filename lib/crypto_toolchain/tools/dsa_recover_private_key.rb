module CryptoToolchain
  module Tools
    class DSARecoverPrivateKey
      def initialize(public_key: , message: , r: , s: , p: DSA_P, q: DSA_Q, g: DSA_G)
        @public_key = numberize(public_key)
        @r = numberize(r)
        @s = numberize(s)
        @message = message
      end

      attr_reader :public_key, :message, :r, :s

      def find_k
        #     (s * k) - H(msg)
        # x = ----------------  mod q
        #             r
        kp = CryptoToolchain::BlackBoxes::DSAKeypair.new
        (1..0x0000ffff).each do |k|
          numerator = (s * k) - CryptoToolchain::SHA1.digest(message).to_number
          denominator = r.invmod(q)
          x = (numerator * denominator) % q

        end

      end

      def execute
      end
    end
  end
end
