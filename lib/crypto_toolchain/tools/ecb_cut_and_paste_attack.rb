module CryptoToolchain
  module Tools
    class EcbCutAndPasteAttack
      include DetermineBlocksize
      def initialize(replace: "user",
                     with: "admin",
                     oracle: CryptoToolchain::BlackBoxes::EcbCookieEncryptor.new,
                     initial: "charlesisagood@dog.com"
                    )
        @oracle = oracle
        @replace = replace
        @replacement = with
        @initial = initial
      end

      def execute
        without_text_to_change + replaced_text_only
      end

      private

      attr_reader :oracle, :replace, :replacement, :initial

      def without_text_to_change
        (0...Float::INFINITY).each do |i|
          input = initial + "X" * i
          oracle.profile_for(input).in_blocks(blocksize).each do |block|
            if block.start_with?(replace)
              return oracle.encrypt(input).in_blocks(blocksize)[0..-2].join
            end
          end
        end
      end

      def replaced_text_only
        (0...Float::INFINITY).each do |i|
          input = initial + "X" * i + replacement
          oracle.profile_for(input).in_blocks(blocksize).each_with_index do |block, bi|
            if block.start_with?(replacement)
              return oracle.encrypt(input).in_blocks(blocksize)[bi]
            end
          end
        end
      end
    end
  end
end
