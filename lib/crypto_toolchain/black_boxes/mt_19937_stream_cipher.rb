module CryptoToolchain
  module BlackBoxes
    class MT19937StreamCipher
      MAX_SEED = 0x0000ffff
      def initialize(plaintext, seed: rand(0..MAX_SEED))
        @seed = seed & MAX_SEED
        @prng = CryptoToolchain::BlackBoxes::MT19937.new(@seed)
        @plaintext = plaintext
      end

      def encrypt(str = plaintext)
        str ^ keystream
      end

      def decrypt(str)
        str ^ keystream
      end

      private

      attr_reader :plaintext, :prng, :seed

      def keystream
        return @keystream if defined? @keystream
        @keystream = (0...(plaintext.bytesize)).each_with_object("") do |_, memo|
          memo << (prng.extract & 0x000000ff).chr
        end
      end
    end
  end
end
