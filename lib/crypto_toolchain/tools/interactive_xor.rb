#encoding ASCII-8BIT
#
# nonce = 0
# key = "a'\xC2[R\xEE\x8F2K\xBA\xCA\x980\x9Bb\xD5"
# _plains = File.read("spec/fixtures/3-19.txt").split("\n").map(&:strip).map(&:from_base64)
# ciphertexts = _plains.map {|pl| pl.encrypt_ctr(key: key, nonce: nonce, blocksize: 16)}
# CryptoToolchain::Tools::InteractiveXor.new(ciphertexts).execute
#
module CryptoToolchain
  module Tools
    class InteractiveXor
      attr_reader :ciphertexts
      def initialize(ciphertexts)
        @ciphertexts = ciphertexts
      end

      def execute
        binding.pry
      end

      def validate_length!(plains)
        len = plains.first.length
        plains.each do |pl|
          raise ArgumentError.new("must have same length") unless pl.length == len
        end
      end

      def keys_for(plains, index)
        plains.map.with_index do |pl|
          len = [pl.length, ciphertexts[index].length].min
          ciphertexts[index][0...len] ^ pl[0...len]
        end
      end

      # index is the index of the ciphertext against which you are making an attempt
      # Plains are the plaintexts you want to try as possibilities
      def attempt(index, *plains)
        validate_length!(plains)
        keys = keys_for(plains, index)
        ciphertexts.each_with_index do |ct, i|
          line = keys.map do |k|
            _len = [ct.bytesize, k.bytesize].min
            ct[0..._len] ^ k[0..._len]
          end.join("     |     ")
          puts "#{i}\t#{line}"
        end
        nil
      end
    end
  end
end
