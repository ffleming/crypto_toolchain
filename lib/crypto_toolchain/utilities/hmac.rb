module CryptoToolchain
  module Utilities
    class HMAC
      class << self
        def digest(message, key: , hash: CryptoToolchain::Utilities::SHA1)
          new(key: key, hash: hash).digest(message)
        end

        def hexdigest(message, key: , hash: CryptoToolchain::Utilities::SHA1)
          new(key: key, hash: hash).hexdigest(message)
        end

      end

      def initialize(key: , hash: , blocksize: nil)
        @key = key
        @hash = hash
        @blocksize = blocksize || determine_blocksize
      end

      def digest(message)
        hash.digest(outer_pad + hash.digest(inner_pad + message))
      end

      def hexdigest(message)
        digest(message).to_hex
      end

      def determine_blocksize
        case hash.to_s.split(':').last.downcase.gsub(/[^a-z0-9]/i, '')
        when /md(4|5)/
          64
        when /sha(1|224|256)/
          64
        else
          raise ArgumentError.new("Unsupported hash #{hash}")
        end
      end

      private

      def outer_pad
        @outer_pad ||= (0x5c.chr * blocksize) ^ blocksize_key
      end

      def inner_pad
        @inner_pad ||= (0x36.chr * blocksize) ^ blocksize_key
      end

      def blocksize_key
        @blocksize_key ||= padded(shortened(key))
      end

      def padded(input)
        if input.bytesize < blocksize
          input.ljust(blocksize, 0.chr)
        else
          input
        end
      end

      def shortened(input)
        if input.bytesize > blocksize
          hash.digest(input)
        else
          input
        end
      end

      attr_reader :blocksize, :key, :hash
    end
  end
end
