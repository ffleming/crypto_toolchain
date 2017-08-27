module CryptoToolchain
  module BlackBoxes
    class AesCtrEditor
      def initialize(plaintext, key: Random.new.bytes(16), nonce: rand(0..0x0000FF))
        @plaintext = plaintext
        @key = key
        @nonce = nonce
        @ciphertext = plaintext.encrypt_ctr(key: key, nonce: nonce)
      end

      # Offset is in bytes
      # Does not mutate @ciphetext or @plaintext
      def edit(offset: ,with: )
        previous = ciphertext[0...offset]
        after = ciphertext[(offset + with.bytesize)..-1]
        edited = with.encrypt_ctr(nonce: nonce,
                                  key: key,
                                  start_counter: offset)
        previous + edited + after
      end

      attr_reader :plaintext, :key, :nonce, :ciphertext
    end
  end
end
