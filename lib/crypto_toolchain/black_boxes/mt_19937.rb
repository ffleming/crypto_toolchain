#encoding: ASCII-8BIT

# Note: 64 bit is untested
module CryptoToolchain
  module BlackBoxes
    class MT19937
      PARAMETERS_32 = {
          w: 32, n: 624, m: 397, r: 31,
          a: 0x9908b0df,
          u: 11, d: 0xFFFFFFFF,
          s: 7,  b: 0x9d2c5680,
          t: 15, c: 0xefc60000,
          l: 18,
          f: 1812433253
        }.freeze
      PARAMETERS_64 = {
        w: 64, n: 312, m: 156, r: 31,
        a: 0xB5026F5AA96619E9,
        u: 29, d: 0x5555555555555555,
        s: 17, b: 0x71D67FFFEDA60000,
        t: 37, c: 0xFFF7EEE000000000,
        l: 43,
        f: 6364136223846793005
      }.freeze

      def initialize(seed, bits: 32)
        @seed = seed
        set_vars!(parameters_for(bits))
        @index = n
        @state = build_state!
      end

      def extract
        twist! if index >= n
        y = state[index]
        y ^= (y >> u) & d
        y ^= (y << s) & b
        y ^= (y << t) & c
        y ^= (y >> l)
        @index += 1
        lowest_bits(y)
      end

      private

      attr_reader(*(PARAMETERS_32.keys))
      attr_reader :seed, :state, :index

      def parameters_for(bits)
        case bits
        when 32
          PARAMETERS_32
        when 64
          PARAMETERS_64
        else
          raise ArgumentError.new("Bits must be 32 or 64")
        end
      end

      def build_state!
        _state = [seed]
        for i in (1...n)
          prev = _state[i - 1]
          val = lowest_bits((f * (prev ^ (prev >> (w-2)) ) + i))
          _state << val
        end
        _state
      end

      def twist!
        for i in (0...n)
          cur = state[i]
          x = (cur & upper_mask) + (state[(i+1) % n] & lower_mask)
          xA = x >> 1
          if (x % 2) != 0
            xA = xA ^ a
          end
          state[i] = state[(i + m) % n] ^ xA
        end
        @index = 0
        nil
      end

      def lower_mask
        @lower_mask ||= (1 << r) - 1
      end

      def upper_mask
        @upper_mask ||= lowest_bits(~lower_mask)
      end

      def set_vars!(parameters)
        parameters.each do |k, v|
          instance_variable_set("@#{k}", v)
        end
      end

      def lowest_bits(num)
        num & 0xffffffff
      end
    end
  end
end
