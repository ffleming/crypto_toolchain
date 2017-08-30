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
        mask = (1 << 32) - 1
        f = proc {|x, y, z| x & y | x.^(mask) & z}
        g = proc {|x, y, z| x & y | x & z | y & z}
        h = proc {|x, y, z| x ^ y ^ z}
        r = proc {|v, s| v.lrot(s) }

        # initial hash
        a, b, c, d = registers_from(state)

        message = original.dup
        length = message.bytesize + append_length

        padding_len = (56 - (length + 1) ) % 64
        str_length = [(length * 8)].pack("Q<")
        padding = (0x80.chr + (0.chr * padding_len) + str_length)

        (message + padding).in_blocks(64).each do |block|
          x = block.unpack("L<16")

          aa, bb, cc, dd = a, b, c, d
          [0, 4, 8, 12].each do |i|
            a = r[a + f[b, c, d] + x[i],  3]; i += 1
            d = r[d + f[a, b, c] + x[i],  7]; i += 1
            c = r[c + f[d, a, b] + x[i], 11]; i += 1
            b = r[b + f[c, d, a] + x[i], 19]
          end
          [0, 1, 2, 3].each do |i|
            a = r[a + g[b, c, d] + x[i] + 0x5a827999,  3]; i += 4
            d = r[d + g[a, b, c] + x[i] + 0x5a827999,  5]; i += 4
            c = r[c + g[d, a, b] + x[i] + 0x5a827999,  9]; i += 4
            b = r[b + g[c, d, a] + x[i] + 0x5a827999, 13]
          end
          [0, 2, 1, 3].each do |i|
            a = r[a + h[b, c, d] + x[i] + 0x6ed9eba1,  3]; i += 8
            d = r[d + h[a, b, c] + x[i] + 0x6ed9eba1,  9]; i -= 4
            c = r[c + h[d, a, b] + x[i] + 0x6ed9eba1, 11]; i += 8
            b = r[b + h[c, d, a] + x[i] + 0x6ed9eba1, 15]
          end
          a = (a + aa) & mask
          b = (b + bb) & mask
          c = (c + cc) & mask
          d = (d + dd) & mask
        end

        [a, b, c, d].pack("L<4")
      end
      alias_method :digest, :bindigest

      private

      attr_reader :original

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
