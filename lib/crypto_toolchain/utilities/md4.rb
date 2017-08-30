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
          0x80.chr + (0.chr * num_null_pad) + [str.bytesize * 8].pack("Q>")
        end
      end

      def initialize(message)
        @original = message
      end

      def hexdigest(state: INITIAL_STATE, append_length: 0)
        bindigest(state: state, append_length: append_length).unpack("H*").join
      end

      # Copied from https://rosettacode.org/wiki/MD4#Ruby
      def bindigest(state: INITIAL_STATE, append_length: 0)
        # functions
        mask = (1 << 32) - 1
        f = proc {|x, y, z| x & y | x.^(mask) & z}
        g = proc {|x, y, z| x & y | x & z | y & z}
        h = proc {|x, y, z| x ^ y ^ z}
        r = proc {|v, s| (v << s).&(mask) | (v.&(mask) >> (32 - s))}

        # initial hash
        a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

        message = original.dup
        bit_len = message.size << 3
        message += "\x80"
        while (message.size % 64) != 56
          message += "\0"
        end
        message = message.force_encoding('ascii-8bit') + [bit_len & mask, bit_len >> 32].pack("L<2")

        if message.size % 64 != 0
          fail "failed to pad to correct length"
        end

        io = StringIO.new(message)
        block = ""

        while io.read(64, block)
          x = block.unpack("L<16")

          # Process this block.
          aa, bb, cc, dd = a, b, c, d
          [0, 4, 8, 12].each {|i|
            a = r[a + f[b, c, d] + x[i],  3]; i += 1
            d = r[d + f[a, b, c] + x[i],  7]; i += 1
            c = r[c + f[d, a, b] + x[i], 11]; i += 1
            b = r[b + f[c, d, a] + x[i], 19]
          }
          [0, 1, 2, 3].each {|i|
            a = r[a + g[b, c, d] + x[i] + 0x5a827999,  3]; i += 4
            d = r[d + g[a, b, c] + x[i] + 0x5a827999,  5]; i += 4
            c = r[c + g[d, a, b] + x[i] + 0x5a827999,  9]; i += 4
            b = r[b + g[c, d, a] + x[i] + 0x5a827999, 13]
          }
          [0, 2, 1, 3].each {|i|
            a = r[a + h[b, c, d] + x[i] + 0x6ed9eba1,  3]; i += 8
            d = r[d + h[a, b, c] + x[i] + 0x6ed9eba1,  9]; i -= 4
            c = r[c + h[d, a, b] + x[i] + 0x6ed9eba1, 11]; i += 8
            b = r[b + h[c, d, a] + x[i] + 0x6ed9eba1, 15]
          }
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

      # Equivalent to [ 0x67452301, 0xefcdaB89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 ] when using registers
      INITIAL_STATE = "67452301efcdab8998badcfe10325476c3d2e1f0".freeze

      def registers_from(hex_str)
        raise ArgumentError.new("Argument must be a hex string") unless hex_str.hex?
        raise ArgumentError.new("Argument must be 40 characters long") unless hex_str.length == 40
        hex_str.from_hex.unpack("L>*")
      end
    end
  end
end
