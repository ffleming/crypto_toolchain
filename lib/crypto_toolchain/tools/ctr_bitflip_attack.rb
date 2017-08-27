# encoding; ASCII-8BIT
module CryptoToolchain
  module Tools
    class CtrBitflipAttack
      def initialize(target: CryptoToolchain::BlackBoxes::CtrBitflipTarget.new)
        @target = target
      end

      def execute
        easy = ":admin<true:" #only need to flip the last bit of bytes at indices 32, 38, 43
        crypted = target.encrypt(easy)
        crypted.
          flip(7, byte_index: 32).
          flip(7, byte_index: 38).
          flip(7, byte_index: 43)
      end

      private

      attr_reader :target

      def prefix
        "comment1=cooking%20MCs;userdata="
      end

      def suffix
        ";comment2=%20like%20a%20pound%20of%20bacon"
      end
    end
  end
end
