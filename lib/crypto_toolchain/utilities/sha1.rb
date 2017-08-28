#encoding: ASCII-8BIT
module CryptoToolchain
  module Utilities
    class SHA1
      class << self
        def hexdigest(str)
          CryptoToolchain::Utilities::SHA1.new(str).hexdigest
        end

        def bindigest(str)
          CryptoToolchain::Utilities::SHA1.new(str).bindigest
        end
      end

      def initialize(message)
        @original = message
      end

      def hexdigest
        @hexdigest ||= bindigest.unpack("H*").join
      end

      def bindigest
        return @bindigest if defined? @bindigest

        h0 = 0x67452301
        h1 = 0xefcdaB89
        h2 = 0x98badcfe
        h3 = 0x10325476
        h4 = 0xc3d2e1f0

        preprocessed.in_blocks(64).each do |_block|
          w = _block.unpack("L>16")
          (16..79).each do |i|
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).lrot(1)
          end
          a = h0
          b = h1
          c = h2
          d = h3
          e = h4
          (0..79).each do |i|
            func, k = f_and_k_for(i)
            f = func.call(b, c, d)
            temp = (a.lrot(5) + f + e + k + w[i]) & 0xffffffff
            e = d
            d = c
            c = b.lrot(30)
            b = a
            a = temp
          end
          h0 = (h0 + a) & 0xffffffff
          h1 = (h1 + b) & 0xffffffff
          h2 = (h2 + c) & 0xffffffff
          h3 = (h3 + d) & 0xffffffff
          h4 = (h4 + e) & 0xffffffff
        end
        @bindigest = [ h0, h1, h2, h3, h4].pack("L>5")
      end

      private

      attr_reader :original

      F_FUNCTIONS = [
        ->(b,c,d) { (b & c) | ((~b) & d) },
        ->(b,c,d) { b ^ c ^ d },
        ->(b,c,d) { (b & c) | (b & d) | (c & d) },
        ->(b,c,d) { b ^ c ^ d },
      ].freeze
      K_CONSTANTS = [
        0x5a827999,
        0x6ed9eba1,
        0x8f1bbcdc,
        0xca62c1d6
      ].freeze
      def constant_lookup(index)
        [F_FUNCTIONS[index], K_CONSTANTS[index]]
      end

      def f_and_k_for(i)
        case i
        when 0..19
          constant_lookup(0)
        when 20..39
          constant_lookup(1)
        when 40..59
          constant_lookup(2)
        when 60..79
          constant_lookup(3)
        else
          raise ArgumentError.new("#{i} out of sensible range 0..79")
        end
      end

      def preprocessed
        @preprocessed ||= padded + [original.bytesize * 8].pack("Q>")
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
        num_null_pad = (56 - (original.bytesize + 1) ) % 64
        @padded = "#{original}\x80#{0.chr * num_null_pad}"
      end
    end
  end
end
