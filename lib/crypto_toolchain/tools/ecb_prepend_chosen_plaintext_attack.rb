# encoding: ASCII-8BIT
module CryptoToolchain
  module Tools
    class EcbPrependChosenPlaintextAttack
      include DetermineBlocksize
      PAD = "A".freeze

      # oracle must return an encrypted string via #encrypt
      def initialize(oracle: CryptoToolchain::BlackBoxes::EcbPrependChosenPlaintextOracle.new)
        @oracle = oracle
        unless oracle.encrypt(PAD * blocksize * 10).is_ecb_encrypted?(@blocksize)
          raise ArgumentError.new("Oracle does not appear to encrypt with ECB")
        end
      end

      def execute
        (0..Float::INFINITY).each_with_object("") do |block_index, solved|
          from_block = (0...blocksize).each_with_object("") do |i, solved_in_block|
            padding_length = blocksize - (solved_in_block.bytes.length) - 1
            padding = PAD * padding_length
            target = oracle.encrypt(padding).in_blocks(blocksize)[block_index]
            dict = (0..255).map(&:chr).each_with_object({}) do |chr, memo|
              guess = padding + solved + solved_in_block + chr
              output = oracle.encrypt(guess).in_blocks(blocksize)[block_index]
              memo[output] = chr
            end
            if !dict.has_key?(target)
              return "#{solved}#{solved_in_block}"
            end
            solved_in_block << dict.fetch(target)
          end
          solved << from_block
        end
      end

      private

      attr_reader :oracle
    end
  end
end
