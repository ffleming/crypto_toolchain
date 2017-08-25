module CryptoToolchain
  module BlackBoxes
    class MT19937StreamCipher
      def initialize(plaintext, seed: rand(0..0x0000ffff))
        @seed = seed & 0x0000ffff
        @prng = CryptoToolchain::BlackBoxes::MT19937.new(@seed)
        @plaintext = plaintext
      end

      def encrypt(str = plaintext)
        plaintext ^ keystream
      end

      def decrypt(str)
        str ^ keystream
      end

      private

      attr_reader :plaintext, :prng

      def keystream
        return @keystream if defined? @keystream
        @keystream = (0...(plaintext.bytesize)).each_with_object("") do |_, memo|
          memo << (prng.extract & 0x000000ff).chr
        end
      end
    end
  end
end
