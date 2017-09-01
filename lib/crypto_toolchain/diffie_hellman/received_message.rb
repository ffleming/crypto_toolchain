module CryptoToolchain
  module DiffieHellman
    class ReceivedMessage
      def initialize(from: , contents: )
        @from = from
        @contents = contents
      end

      def ==(other)
        unless other.is_a?(CryptoToolchain::DiffieHellman::ReceivedMessage)
          raise ArgumentError.new("Cannot coerce #{other.clas} to ReceivedMessage")
        end
      end
      attr_reader :from, :contents
    end
  end
end
