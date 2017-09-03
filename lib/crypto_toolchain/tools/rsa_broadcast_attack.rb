module CryptoToolchain
  module Tools
    class RSABroadcastAttack
      Input = Struct.new(:ciphertext, :public_key)
      def initialize(inputs)
        @e = inputs.length
        @inputs = inputs
      end
      attr_reader :inputs, :e

      def execute
        residues = inputs.map(&:ciphertext)
        mods = inputs.map {|i| i.public_key.n }
        result = chinese_remainder(residues, mods)
        result.root(e).
          to_s(16).
          from_hex
      end
    end
  end
end
