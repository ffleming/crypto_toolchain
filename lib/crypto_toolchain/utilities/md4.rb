#encoding: ASCII-8BIT
module CryptoToolchain
  module Utilities
    class MD4
      class << self
        def hexdigest(str, state: INITIAL_STATE, append_length: 0 )
          CryptoToolchain::Utilities::MD4.new(str).hexdigest(state: state, append_length: append_length)
        end

        def bindigest(str, state: INITIAL_STATE, append_length: 0)
          CryptoToolchain::Utilities::MD4.new(str).bindigest(state: state, append_length: append_length)
        end
        alias_method :digest, :bindigest

        def padding(str)
          num_null_pad = (56 - (str.bytesize + 1) ) % 64
          0x80.chr + (0.chr * num_null_pad) + [(str.bytesize * 8)].pack("Q<")
        end
      end

      def initialize(message)
        @original = message
      end

      def hexdigest(state: INITIAL_STATE, append_length: 0)
        bindigest(state: state, append_length: append_length).unpack("H*").join
      end

      # Copied from https://rosettacode.org/wiki/MD4#Ruby, with minor modifications
      def bindigest(state: INITIAL_STATE, append_length: 0)
        running_state = registers_from(state)

        length = original.bytesize + append_length

        padding_len = (56 - (length + 1) ) % 64
        str_length = [(length * 8)].pack("Q<")
        padding = (0x80.chr + (0.chr * padding_len) + str_length)

        (original + padding).in_blocks(64).each do |block|
          x = block.unpack("L<16")

          a, b, c, d = running_state
          [0, 4, 8, 12].each do |i|
            a = (a + f(b, c, d) + x[i]).lrot(3)
            d = (d + f(a, b, c) + x[i+1]).lrot(7)
            c = (c + f(d, a, b) + x[i+2]).lrot(11)
            b = (b + f(c, d, a) + x[i+3]).lrot(19)
          end
          [0, 1, 2, 3].each do |i|
            a = (a + g(b, c, d) + x[i] + 0x5a827999).lrot(3)
            d = (d + g(a, b, c) + x[i+4] + 0x5a827999).lrot(5)
            c = (c + g(d, a, b) + x[i+8] + 0x5a827999).lrot(9)
            b = (b + g(c, d, a) + x[i+12] + 0x5a827999).lrot(13)
          end
          [0, 2, 1, 3].each do |i|
            a = (a + h(b, c, d) + x[i] + 0x6ed9eba1).lrot(3)
            d = (d + h(a, b, c) + x[i+8] + 0x6ed9eba1).lrot(9)
            c = (c + h(d, a, b) + x[i+4] + 0x6ed9eba1).lrot(11)
            b = (b + h(c, d, a) + x[i+12] + 0x6ed9eba1).lrot(15)
          end

          [a, b, c, d].each_with_index do |val, i|
            running_state[i] = (running_state[i] + val) & 0xffffffff
          end
        end

        running_state.pack("L<4")
      end
      alias_method :digest, :bindigest

      private

      attr_reader :original

      def f(x, y, z)
         (x & y) | (~x & z)
      end

      def g(x, y, z)
        (x & y) | (x & z) | (y & z)
      end

      def h(x, y, z)
        x ^ y ^ z
      end

      # Equivalent to [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 ]
      INITIAL_STATE = "0123456789abcdeffedcba9876543210"

      def registers_from(hex_str)
        raise ArgumentError.new("Argument must be a hex string") unless hex_str.hex?
        raise ArgumentError.new("Argument must be 32 characters long") unless hex_str.length == 32
        hex_str.from_hex.unpack("L<4")
      end
    end
  end
end
