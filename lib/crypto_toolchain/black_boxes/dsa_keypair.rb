module CryptoToolchain
  module BlackBoxes
    class DSAKeypair
      def initialize(p: DSA_P, q: DSA_Q, g: DSA_G, private_key: nil)
        @p = p
        @q = q
        @g = g
        @private_key = private_key
      end

      attr_reader :p, :q, :g

      def sign(m, max_k: q)
        r = s = 0
        loop do
          k = rand(2...max_k)
          r = g.modpow(k, p) % q
          next if r == 0
          digest = CryptoToolchain::Utilities::SHA1.digest(m).to_number
          s = k.modinv(q) * ( digest + (private_key * r)) % q
          next if s == 0
          return [r.to_bin_string, s.to_bin_string]
        end
      end

      def verify(m, r: , s: , public_key: self.public_key)
        s = s.to_number
        r = r.to_number
        return false unless(0 < r && r < q) && (0 < s && s < q)
        w = s.invmod(q)
        u_1 = (CryptoToolchain::Utilities::SHA1.digest(m).to_number * w) % q
        u_2 = (r * w) % q
        # a*b % n = [(a % n) * (b % n)] % m
        v = ((g.modpow(u_1, p) * public_key.modpow(u_2, p)) % p) % q
        v == r
      end

      def private_key
        @private_key ||= rand(1..DSA_Q)
      end

      def public_key
        @public_key ||= g.modpow(private_key, p)
      end
    end
  end
end
