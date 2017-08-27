# encoding; ASCII-8BIT
module CryptoToolchain
  module Tools
    class CbcIvEqualsKeyAttack
      attr
      def initialize(target: CryptoToolchain::BlackBoxes::CbcIvEqualsKeyTarget.new,
                     message_prefix: "Invalid byte in ")
        @target = target
        @message_prefix = message_prefix
      end

      def execute
        initial = ("A" * CryptoToolchain::AES_BLOCK_SIZE * 3)
        blocks = target.encrypt(initial).in_blocks(CryptoToolchain::AES_BLOCK_SIZE)
        mal = blocks[0] + (0.chr * 16) + blocks[0]
        begin
          target.is_admin?(mal)
        rescue RuntimeError => e
          blocks = e.message[(message_prefix.length)..-1].in_blocks(CryptoToolchain::AES_BLOCK_SIZE)
          blocks[0] ^ blocks[2]
        end
      end

      private

      attr_reader :target, :message_prefix

    end
  end
end
