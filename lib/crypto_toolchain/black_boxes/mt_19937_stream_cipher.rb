module CryptoToolchain
  module BlackBoxes
    class MT19937StreamCipher
      MAX_SEED = 0x0000ffff
      class << self
        def max_seed
          @max_seed ||= MAX_SEED
        end

        def max_seed=(val)
          @max_seed = val
        end
      end

      def self.generate_token(length: 32, seed: Time.now.to_i)
        new("A" * length, seed: seed).keystream.to_base64
      end

      def initialize(plaintext, seed: rand(0..(self.class.max_seed)))
        @seed = seed & self.class.max_seed
        @prng = CryptoToolchain::Utilities::MT19937.new(@seed)
        @plaintext = plaintext
      end

      def encrypt(str = plaintext)
        str ^ keystream
      end

      def decrypt(str)
        str ^ keystream
      end

      def keystream
        return @keystream if defined? @keystream
        _keystream = (0..(plaintext.bytesize / 4)).each_with_object("") do |_, memo|
          memo << [prng.extract].pack("L")
        end
        @keystream = _keystream[0...(plaintext.bytesize)]
      end

      private

      attr_reader :plaintext, :prng, :seed

    end
  end
end
