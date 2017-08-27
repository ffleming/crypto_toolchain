# encoding; ASCII-8BIT
module CryptoToolchain
  module BlackBoxes
    class CtrBitflipTarget
      def initialize(key: Random.new.bytes(16), nonce: rand(0..0x0000FFFF))
        @key = key
        @nonce = nonce
      end

      def encrypt(input)
        str = prefix + input.gsub(/;|=/, "") + suffix
        str.encrypt_ctr(key: key,  nonce: nonce)
      end

      def is_admin?(crypted)
        crypted.decrypt_ctr(key: key, nonce: nonce).include?(";admin=true;")
      end

      private

      attr_reader :key, :nonce

      def prefix
        "comment1=cooking%20MCs;userdata="
      end

      def suffix
        ";comment2=%20like%20a%20pound%20of%20bacon"
      end
    end
  end
end
