module CryptoToolchain
  module BlackBoxes
    class SHA1Mac
      attr_reader :key

      def initialize(key: Random.new.bytes(16))
        @key = key
      end

      def mac(str)
        concat = key + str
        CryptoToolchain::Utilities::SHA1.hexdigest(concat)
      end

      def valid?(message: , mac: )
        self.mac(message) == mac
      end
    end
  end
end
