# encoding; ASCII-8BIT
module CryptoToolchain
  module BlackBoxes
    class CbcBitflipTarget
      def initialize(key: Random.new.bytes(16), iv: Random.new.bytes(16))
        @key = key
        @iv = iv
      end

      def encrypt(input)
        str = prefix + input.gsub(/;|=/, "") + suffix
        str.encrypt_cbc(key: key, blocksize: 16, iv: iv)
      end

      def is_admin?(crypted)
        dec = crypted.decrypt_cbc(key: key, blocksize: 16, iv: iv)
        dec.include?(";admin=true;")
      end

      def flip(block, byte, bit)
        new_byte = ((1 << (bit - 8)) ^ (block[byte].ord)).chr
        block[0...byte] + new_byte + block[(byte+1)..-1]
      end

      def self_own
        easy = ":admin<true:" #only need to flip the last bit of bits 1, 7, 12
        blocks = encrypt(easy).in_blocks(16)
        first = flip(blocks[1], 0, 8)
        equals = flip(first, 6, 8)
        last = flip(equals, 11, 8)
        blocks[1] = last
        is_admin?(blocks.join)
      end

      private

      attr_reader :key, :iv

      def prefix
        "comment1=cooking%20MCs;userdata="
      end

      def suffix
        ";comment2=%20like%20a%20pound%20of%20bacon"
      end
    end
  end
end
