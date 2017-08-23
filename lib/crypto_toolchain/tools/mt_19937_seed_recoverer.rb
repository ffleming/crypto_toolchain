module CryptoToolchain
  module Tools
    class MT19937SeedRecoverer
      def initialize(extracted, start: default_start, finish: Time.now.to_i)
        @extracted = extracted
        @start = start
        @finish = finish
      end

      def execute
        (start..finish).each do |seed|
          if CryptoToolchain::BlackBoxes::MT19937.new(seed).extract == extracted
            return seed
          end
        end
        raise RuntimeError, "Did not find the seed; consider expanding start and finish"
      end

      attr_reader :extracted, :start, :finish

      # One hour ago
      def default_start
        Time.now.to_i - (3600)
      end
    end
  end
end
