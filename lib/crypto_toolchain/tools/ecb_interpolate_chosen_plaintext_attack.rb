# encoding: ASCII-8BIT
module CryptoToolchain
  module Tools
    class EcbInterpolateChosenPlaintextAttack
      include DetermineBlocksize
      PAD = "A".freeze

      # oracle must return an encrypted string via #encrypt
      def initialize(oracle: CryptoToolchain::BlackBoxes::EcbInterpolateChosenPlaintextOracle.new)
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
            target = oracle_encrypt(padding).in_blocks(blocksize)[block_index + prefix_offset]
            dict = (0..255).map(&:chr).each_with_object({}) do |chr, memo|
              guess = padding + solved + solved_in_block + chr
              output = oracle_encrypt(guess).in_blocks(blocksize)[block_index + prefix_offset]
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

      def oracle_encrypt(str)
        oracle.encrypt(PAD * prefix_padding_length + str)
      end

      def prefix_offset
        @prefix_offset ||= large_padding.index(first_repeated_block)
      end

      def large_padding(large_pad_size = 1024)
        @large_padding ||= oracle.encrypt(PAD * large_pad_size).in_blocks(blocksize)
      end

      def first_repeated_block
        @first_repeated_block ||= large_padding.
          group_by(&:itself).
          sort_by {|k, v| v.length }.
          last.
          first
      end

      def prefix_padding_length
        return @prefix_padding_length if defined?(@prefix_padding_length)
        (0..Float::INFINITY).each do |i|
          if oracle.encrypt(PAD * i).in_blocks(blocksize).include?(first_repeated_block)
            @prefix_padding_length = i - blocksize
            return @prefix_padding_length
          end
        end
      end

      def prefix_size
        original_length = oracle.encrypt(PAD * blocksize).length
        (0..Float::INFINITY).each do |i|
          padding = (PAD * blocksize) + (PAD * i)
          len = oracle.encrypt(padding).length
          if len != original_length
            return padding.length
          end
        end
      end
    end
  end
end
