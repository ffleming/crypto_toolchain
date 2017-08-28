module CryptoToolchain
  module BlackBoxes
    class SHA1Mac
      attr_reader :key

      def initialize(key: Random.new.bytes(16))
        @key = key
      end

      def mac(str)
        CryptoToolchain::Utilities::SHA1.hexdigest(key + str)
      end
    end
  end
end
