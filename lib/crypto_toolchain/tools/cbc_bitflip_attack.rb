# encoding; ASCII-8BIT
module CryptoToolchain
  module Tools
    class CbcBitflipAttack
      def initialize(target: CryptoToolchain::BlackBoxes::CbcBitflipTarget.new)
        @target = target
      end

      def flip(block, byte, bit)
        new_byte = ((1 << (bit - 8)) ^ (block[byte].ord)).chr
        block[0...byte] + new_byte + block[(byte+1)..-1]
      end

      def execute
        easy = ":admin<true:" #only need to flip the last bit of bytes 1, 7, 12
        blocks = target.encrypt(easy).in_blocks(16)
        first = flip(blocks[1], 0, 8)
        equals = flip(first, 6, 8)
        last = flip(equals, 11, 8)
        blocks[1] = last
        blocks.join
      end

      private

      attr_reader :target
    end

  end
end
