# encoding; ASCII-8BIT
module CryptoToolchain
  module BlackBoxes
    class CbcIvEqualsKeyTarget
      def initialize(key: Random.new.bytes(16))
        @key = key
      end

      def encrypt(input)
        str = prefix + input.gsub(/;|=/, "") + suffix
        str.encrypt_cbc(key: key, blocksize: 16, iv: key)
      end

      def is_admin?(crypted)
        dec = crypted.decrypt_cbc(key: key, blocksize: 16, iv: key)
        dec.each_byte do |byte|
          raise RuntimeError.new("Invalid byte in #{dec}") if byte > '~'.ord
        end
        dec.include?(";admin=true;")
      end

      private

      attr_reader :key

      def prefix
        "comment1=cooking%20MCs;userdata="
      end

      def suffix
        ";comment2=%20like%20a%20pound%20of%20bacon"
      end
    end
  end
end
