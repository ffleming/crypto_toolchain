#encoding: ASCII-8BIT
module CryptoToolchain
  module Utilities
    class SHA1
      class << self
        def hexdigest(str)

        end
      end

      def initialize(message)
        @original = message
      end

      def hexdigest
        return @hexdigest if defined? @hexdigest
        preprocessed.in_blocks(64) do |_block|

        end
      end
      private

      attr_reader :original

      def extended
        return @extended if defined? @extended
        blocks = preprocessed.in_blocks(64)
        blocks = (16..79).map do |i|

        end

      end

      def preprocessed(str)
        @preprocessed ||= padded + [str.bytesize].pack("Q>")
      end

      def padded
        return @padded if defined? @padded
        # We know that we're dealing with a bitlength that is a multiple of 8
        # because we're working with chars.  To pad with a 1-bit, just go ahead
        # and also pad with 7 0-bits.  That way we can just work with bytes
        #
        # The full message, including an 8-byte (64 bit) length segment, must
        # be a multiple of 64 bytes (512 bits).  So pad such that
        # str.length % 56 = 0.
        num_null_pad = (56 - (str.bytesize % 64) )
        @padded = "#{original}\x80#{0.chr * num_null_pad}"
      end

    end
  end
end
