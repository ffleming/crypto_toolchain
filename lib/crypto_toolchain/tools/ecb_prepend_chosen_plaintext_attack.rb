# encoding: ASCII-8BIT
module CryptoToolchain
  module Tools
    class EcbPrependChosenPlaintextAttack
      include DetermineBlocksize
      # oracle must return an encrypted string via #encrypt
      PAD = "A".freeze
      attr_reader :ciphertext
      def initialize(ciphertext, oracle: )
        @ciphertext = ciphertext
        @oracle = oracle
        unless oracle.encrypt(PAD * blocksize * 2).is_ecb_encrypted?(@blocksize)
          raise ArgumentError.new("Ciphertext does not appear to be encrypted with ECB")
        end
      end

      def execute
        ciphertext.in_blocks(blocksize).each_with_index.with_object("") do |(_, block_index), solved|
          from_block = (0...blocksize).each_with_object("") do |i, solved_in_block|
            padding_length = blocksize - (solved_in_block.bytes.length) - 1
            padding = PAD * padding_length
            target = oracle.encrypt(padding).in_blocks(blocksize)[block_index]
            dict = (1..255).map(&:chr).each_with_object({}) do |chr, memo|
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
