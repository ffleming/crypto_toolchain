# encoding: ASCII-8BIT
module CryptoToolchain
  module Extensions
    module Integer
      def to_hex_string
        ret = to_s(16)
        if ret.length.odd?
          ret = "0#{ret}"
        end
        ret
      end

      def to_bin_string
        to_hex_string.from_hex
      end

      def to_bits(pack_arg = "L>")
        [self].pack(pack_arg).to_bits
      end

      def lrot(num)
        ((self << num) & 0xffffffff) |
          ((self & 0xffffffff) >> (32 - num))
      end

      def rrot(num)
        ((self & 0xffffffff) >> num) |
          ((self << (32 - num)) & 0xffffffff)
      end

      # From Wikipedia:
      # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
      def invmod(n)
        a = self
        t = 0
        new_t = 1
        r = n
        new_r = a
        while new_r != 0
          quotient = r / new_r
          t, new_t = new_t, (t - quotient * new_t)
          r, new_r = new_r, (r - quotient * new_r)
        end
        raise ArgumentError.new("#{self} is not invertible") if r > 1
        t += n if t < 0
        t
      end
      alias_method :mod_inverse, :invmod
      alias_method :modinv, :invmod

      # https://rosettacode.org/wiki/Nth_root#Ruby
      # (with modifications)
      ROUNDING = %i(up down none)
      def root(n, round: :down)
        raise ArgumentError.new("round must be in [#{ROUNDING.join(', ')}]") unless ROUNDING.include?(round)
        raise ArgumentError.new("Can't be called on 0") if self == 0
        x = self
        loop do
          prev = x
          x = ((n - 1) * prev) + (self / (prev ** (n - 1)))
          x /= n
          break if (prev - x) <= 0
        end
        if x**n == self
          x
        else
          case round
          when :up
            x+1
          when :down
            x
          when :none
            raise ArgumentError.new("#{self} has no #{n}th root")
          end
        end
      end

      def modexp(exponent, mod)
        raise ArgumentError.new("Exponent must be non-negative") if exponent < 0
        product = 1
        base = self % mod
        while exponent > 0
          if exponent & 0x01 == 1
            product = (product * base) % mod
          end
          exponent = exponent >> 1
          base = (base**2) % mod
        end
        product
      end
      alias_method :modpow, :modexp

      def updiv(other)
        quot, remainder = self.divmod(other)
        if remainder == 0
          quot
        else
          quot + 1
        end
      end

    end
  end
end

class Integer
  include CryptoToolchain::Extensions::Integer
end
