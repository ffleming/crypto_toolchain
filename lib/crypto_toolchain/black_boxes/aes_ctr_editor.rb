module CryptoToolchain
  module BlackBoxes
    class AesCtrEditor
      def initialize(plaintext, key: Random.new.bytes(16), nonce: Random.new.bytes(16))
        @plaintext = plaintext
        @key = key
        @nonce = nonce
        @ciphertext = plaintext.encrypt_ctr(key: key, nonce: nonce, blocksize: 16)
      end

      # Offset is in bytes
      # Does not mutate @ciphetext or @plaintext
      def edit(offset: nil, block_offset: nil, with: )
        raise ArgumentError.new("Must specify offset or block_offset") if offset.nil? && block_offset.nil?
        if !offset.nil? && offset % CryptoToolchain::AES_BLOCK_SIZE != 0
          raise ArgumentError.new("Offset must align to a block")
        end
        _blocks = ciphertext.in_blocks
        if block_offset.nil?
          block_offset = (offset / 16)
        end
        blocks_to_edit, remainder = with.bytesize.divmod(CryptoToolchain::AES_BLOCK_SIZE)
        if remainder > 0
          blocks_to_edit += 1
        end
        previous = _blocks[0...block_offset].join
        after = _blocks[(block_offset + blocks_to_edit)..-1].join
        edited = with.encrypt_ctr(nonce: nonce,
                                  key: key,
                                  start_counter: block_offset,
                                  blocksize: CryptoToolchain::AES_BLOCK_SIZE)
        previous + edited + after
      end

      attr_reader :plaintext, :key, :nonce, :ciphertext
    end
  end
end
