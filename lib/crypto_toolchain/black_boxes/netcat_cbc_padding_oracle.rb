module CryptoToolchain
  module BlackBoxes
    class NetcatCbcPaddingOracle

      attr_reader :ciphertext

      def initialize(key: Random.new.bytes(16), iv: Random.new.bytes(16))
        @key = key
        @iv = iv
        @ciphertext = Base64.strict_decode64('SNXIDUFQW0Ul6GXI4NyU/LMHl+vRlVIYp4pvFstfpP1n1C9Xhbl/bNip6mK5l7TMPS+vw247XTYK3LKIGT4AZVh6zUB97fN3fOamkLvzpmA=')
      end

      def execute(str)
        handle = IO.popen(["nc", "bufferoverflow.disappointedmama.com", '6767'], "r+")
        handle.puts(Base64.strict_encode64(str))
        resp = handle.readpartial(1024).strip
        handle.close
        case resp
        when "Failed to decrypt the message"
          false
        when "Successfully received and decrypted the message"
          true
        else
          raise StandardError.new, "Unknown response `#{res}`"
        end
      end

      private

      attr_reader :key, :iv
    end
  end
end
