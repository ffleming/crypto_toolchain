module CryptoToolchain
  module Tools
    # Recovers private key from message signatures signed with the same nonce (k)
    # This means that they have the same r values
    class DSARecoverNonceFromSignatures
      class Input
        def initialize(r: , s: , message: )
          @r = r.to_i
          @s = s.to_i
          @message = message
          @hash = CryptoToolchain::Utilities::SHA1.hexdigest(message)
        end
        attr_reader :r, :s, :message, :hash
      end

      def initialize(inputs, q: DSA_Q)
        @targets = targets_for(inputs)
        validate_targets!
        @q = q
      end
      attr_reader :targets, :q

      def execute(params: true)
        t1 = targets.first
        t2 = targets.last
        m1 = t1.hash.hex
        m2 = t2.hash.hex
        s1 = t1.s
        s2 = t2.s
        # (a + b) mod n = [(a mod n) + (b mod n)] mod n.
        top = (m1 - m2) % q
        k = top * (s1 - s2).invmod(q)
        # numerator = ((m1 % q) - (m2 % q)) % q
        k
      end

      def validate_targets!
        r1 = targets.first.r
        targets[1..-1].each do |t|
          raise ArgumentError.new("All r-values must be identical") unless t.r == r1
        end
      end

      def targets_for(inputs)
        inputs.
          group_by {|inp| inp.r }.
          select {|k, v| v.length > 1 }.
          values.
          first
      end
    end
  end
end
