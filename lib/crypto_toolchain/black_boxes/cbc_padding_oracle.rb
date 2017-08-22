module CryptoToolchain
  module BlackBoxes
    class CbcPaddingOracle

      attr_reader :ciphertext, :plaintext

      def initialize(key: Random.new.bytes(16), iv: Random.new.bytes(16))
        @key = key
        @iv = iv
        @ciphertext = text.encrypt_cbc(key: key, iv: iv, blocksize: 16)
        @plaintext = text
      end

      def execute(str)
        begin
          !!str.
            decrypt_cbc(key: key, iv: iv, blocksize: 16, strip_padding: false).
            without_pkcs7_padding(16, raise_error: true)
        rescue ArgumentError
          false
        end
      end

      private

      attr_reader :key, :iv

      def text
        @text ||= %w(
          MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
          MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
          MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
          MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
          MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
          MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
          MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
          MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
          MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
          MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
        ).map(&:from_base64).sample
      end
    end
  end
end
