module CryptoToolchain
  module BlackBoxes
    class RSAParityOracle
      def initialize(keypair)
        @keypair = keypair
      end
      attr_reader :keypair

      def execute(ciphertext)
        keypair.decrypt(ciphertext).to_number & 1
      end
    end
  end
end
