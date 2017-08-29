#encoding: ASCII-8BIT
module CryptoToolchain
  module Utilities
    class SHA1
      class << self
        def hexdigest(str, registers: STARTING_REGISTERS, append_length: nil )
          CryptoToolchain::Utilities::SHA1.new(str).hexdigest(registers: registers, append_length: append_length)
        end

        def bindigest(str, registers: STARTING_REGISTERS, append_length: nil)
          CryptoToolchain::Utilities::SHA1.new(str).bindigest(registers: registers, append_length: append_length)
        end
        alias_method :digest, :bindigest

        def padding(str)
          num_null_pad = (56 - (str.bytesize + 1) ) % 64
          0x80.chr + (0.chr * num_null_pad) + [str.bytesize * 8].pack("Q>")
        end

        def registers_for(hex_str)
          raise ArgumentError.new("Argument must be a hex string") unless hex_str.hex?
          raise ArgumentError.new("Argument must be 160 characters long") unless hex_str.length == 40
          hex_str.from_hex.in_blocks(4).flat_map { |block| block.unpack("L>") }
        end
      end

      def initialize(message)
        @original = message
      end

      def hexdigest(registers: STARTING_REGISTERS, append_length: nil)
        bindigest(registers: registers, append_length: append_length).unpack("H*").join
      end

      def bindigest(registers: STARTING_REGISTERS, append_length: nil)
        unless registers.is_a?(Array) && registers.length == 5
          raise ArgumentError.new("registers must be a 5-element array")
        end
        h = registers.dup

        length = if append_length.nil?
                   original.bytesize
                 else
                   original.bytesize + append_length
                 end
        num_null_pad = (56 - (length + 1) ) % 64
        padding = 0x80.chr + (0.chr * num_null_pad) + [length * 8].pack("Q>")

        (original + padding).in_blocks(64).each do |_block|
          w = _block.unpack("L>16")
          (16..79).each do |i|
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).lrot(1)
          end

          a, b, c, d, e = h

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

          [a, b, c, d, e].each_with_index do |val, i|
            h[i] = (h[i] + val) & 0xffffffff
          end
        end
        h.pack("L>5")
      end
      alias_method :digest, :bindigest

      # def padding
      #   return @padding if defined? @padding
        # We know that we're dealing with a bitlength that is a multiple of 8
        # because we're working with chars.  To pad with a 1-bit, just go ahead
        # and also pad with 7 0-bits.  That way we can just work with bytes
        #
        # The full message, including an 8-byte (64 bit) length segment, must
        # be a multiple of 64 bytes (512 bits).  So pad such that
        # str.length % 56 = 0.
      #   num_null_pad = (56 - (original.bytesize + 1) ) % 64
      #   @padding = 0x80.chr + (0.chr * num_null_pad) + [original.bytesize * 8].pack("Q>")
      # end

      private

      attr_reader :original

      F_FUNCTIONS = [
        ->(b,c,d) { (b & c) | ((~b) & d) },
        ->(b,c,d) { b ^ c ^ d },
        ->(b,c,d) { (b & c) | (b & d) | (c & d) },
        ->(b,c,d) { b ^ c ^ d },
      ].freeze

      K_CONSTANTS = [ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 ].freeze

      CONSTANTS = F_FUNCTIONS.zip(K_CONSTANTS).freeze

      STARTING_REGISTERS = [ 0x67452301, 0xefcdaB89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 ].freeze

      def f_and_k_for(i)
        raise ArgumentError.new("i must be in 0..79") unless i >=0 && i <= 79
        CONSTANTS[i/20]
      end
    end
  end
end
