module CryptoToolchain
  module BlackBoxes
    class EcbOrCbcEncryptor
      ENCRYPTION_ALGORITHMS = %i(ebc cbc).freeze
      attr_reader :key, :plaintext

      def initialize(plaintext, algorithm: random_algorithm)
        raise ArgumentError.new("Unsupported algorithm #{algorithm}") unless ENCRYPTION_ALGORITHMS.include? algorithm
        @plaintext = plaintext
        @key = String.random_bytes(16)
        @algorithm = algorithm
      end

      def encrypt(_algo = algorithm)
        case _algo
        when :ecb
          encrypt_ecb
        when :cbc
          encrypt_cbc
        end
      end

      private

      def obfuscate(text)
        append_len = (rand(5..10))
        prepend_len = (rand(5..10))
        "#{String.random_bytes(append_len)}#{text}#{String.random_bytes(prepend_len)}"
      end

      def encrypt_ecb
        obfuscate(plaintext).encrypt_ecb(key: key, blocksize: 16)
      end

      def encrypt_cbc
        obfuscate(plaintext).encrypt_cbc(key: key,
                              iv: String.random_bytes(16),
                              blocksize: 16)
      end

      def random_algorithm
        ENCRYPTION_ALGORITHMS[rand(2)]
      end
    end

  end
end
