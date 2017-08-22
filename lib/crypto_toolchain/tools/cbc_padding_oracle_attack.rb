# encoding: ASCII-8BIT
module CryptoToolchain
  module Tools
    class CbcPaddingOracleAttack
      def initialize(oracle: , blocksize: 16)
        @oracle = oracle
        @blocksize = blocksize
      end

      def execute
        _blocks = ciphertext.in_blocks(blocksize)
        _blocks[1..-1].map.with_index(1) do |block, i|
          preceding = _blocks[i - 1]
          intermediate = intermediate_block(preceding: preceding, target: block)
          intermediate ^ preceding
        end.
          join.
          without_pkcs7_padding(blocksize)
      end

      private

      attr_reader :oracle, :blocksize

      def ciphertext
        @ciphertext ||= oracle.ciphertext
      end

      private

      def intermediate_block(preceding: , target: )
        intermediate = "\x00" * target.size
        (0...target.bytesize).to_a.each do |i|
          intermediate = build_intermediate(
            index: ((target.bytesize - 1) - i),
            target: target,
            preceding: preceding,
            intermediate: intermediate)
        end
        intermediate
      end

      def intermediate_block(preceding: , target: )
        range = Array(0...blocksize).reverse
        range.each_with_object(0x00.chr * blocksize) do |index, memo|
          pad = blocksize - index
          padding = (pad.chr * pad).rjust(blocksize, 0x00.chr)
          candidate = padding ^ memo ^ preceding
          (0..255).each do |guess|
            next if (preceding.bytes[index] == guess && index == blocksize - 1)
            candidate = padding ^ memo
            candidate[index] = guess.chr
            attempt = candidate + target
            if oracle.execute(attempt)
              memo[index] = (guess ^ pad).chr
              break
            end
          end
        end
      end
    end
  end
end
