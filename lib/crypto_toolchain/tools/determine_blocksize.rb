module CryptoToolchain
  module Tools
    module DetermineBlocksize
      def blocksize
        return @blocksize if defined?(@blocksize)
        original_size = oracle.encrypt("A").length
        i = 2
        loop do
          plain = "A" * i
          len = oracle.encrypt(plain).length
          if len != original_size
            @blocksize = len - original_size
            return @blocksize
          end
          i += 1
        end
      end
    end
  end
end
