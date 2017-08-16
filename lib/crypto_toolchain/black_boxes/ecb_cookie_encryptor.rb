# encoding: ASCII-8BIT
class Hash
  def symbolize_keys
    map do |k, v|
      [k.to_sym, v]
    end.to_h
  end
end

module CryptoToolchain
  module BlackBoxes
    class EcbCookieEncryptor
      def initialize(key: String.random_bytes(16))
        @key = key
      end

      def cookie_for(email)
        {
          email: email.gsub(/&|=/, ""),
          uid: 10,
          role: "user"
        }.each_with_object([]) do |(k, v), memo|
          memo << "#{k}=#{v}"
        end.join("&")
      end
      alias_method :profile_for, :cookie_for

      def encrypted_profile_for(email)
        profile_for(email).encrypt_ecb(key: key, blocksize: 16)
      end
      alias_method :encrypt, :encrypted_profile_for

      def decrypt(enc)
        enc.
          decrypt_ecb(key: key, blocksize: 16).
          split("&").
          map do |str|
            k, v = str.split("=")
            [k, v || ""]
          end.
          to_h.
          symbolize_keys
      end

      private

      attr_reader :key
    end
  end
end
