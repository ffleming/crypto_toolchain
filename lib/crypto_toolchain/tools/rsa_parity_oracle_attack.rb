module CryptoToolchain
  module Tools
    class RSAParityOracleAttack
      def initialize(oracle: , n: , e: 3)
        @oracle = oracle
        @n = n
        @e = e
      end
      attr_reader :n, :oracle, :e

      def execute(_ciphertext, output: false)
        ciphertext = _ciphertext.to_number
        min = BigDecimal(0)
        max = BigDecimal(n)
        mid = max/2
        mult = 2.modpow(e, n)
        Math.log2(n).ceil.times do
          mid = (min + max) / 2
          ciphertext = ((ciphertext) * mult) % n
          if oracle.execute(ciphertext.to_bin_string) == 0
            max = mid
          else
            min = mid
          end
          if output
            print "\e[2J\e[f\r#{max.to_i.to_bin_string.gsub(/[^[:print:]]/, '*')}"
          end
        end
        max.to_i.to_bin_string
      end
    end
  end
end
