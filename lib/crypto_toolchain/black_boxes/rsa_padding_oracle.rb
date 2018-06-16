module CryptoToolchain
  module BlackBoxes
    class RSAPaddingOracle
      def initialize(keypair: CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 256))
        @keypair = keypair
      end

      attr_reader :keypair

      def execute(str)
        keypair.
          decrypt(str, pad: true).
          is_pkcs1_5_padded?(keypair.bits)
      end
    end
  end
end
