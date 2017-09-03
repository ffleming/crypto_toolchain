module CryptoToolchain
  module BlackBoxes
    class RSAUnpaddedMessageRecoveryOracle

      attr_reader :keypair

      def initialize(keypair: CryptoToolchain::BlackBoxes::RSAKeypair.new)
        @keypair = keypair
        @seen = []
      end

      def execute(ciphertext)
        hsh = Digest::SHA256.hexdigest(ciphertext)
        raise ArgumentError.new("Already decrypted") if @seen.include?(hsh)
        @seen << hsh
        keypair.decrypt(ciphertext)
      end

      def encrypt(ciphertext)
        keypair.encrypt(ciphertext, to: keypair.public_key)
      end
    end
  end
end
