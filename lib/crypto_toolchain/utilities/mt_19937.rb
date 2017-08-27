#encoding: ASCII-8BIT

# Note: 64 bit is untested
module CryptoToolchain
  module Utilities
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

      def self.from_array(arr, bits: 32, index: parameters_for(bits).fetch(:n))
        mt = new(0, bits: bits)
        mt.send(:state=, arr)
        mt.send(:index=, index)
        mt
      end

      def self.parameters_for(bits)
        case bits
        when 32
          PARAMETERS_32
        when 64
          PARAMETERS_64
        else
          raise ArgumentError.new("Bits must be 32 or 64")
        end
      end

      def initialize(seed, bits: 32)
        @seed = seed
        set_vars!(self.class.parameters_for(bits))
        @index = n
        @state = build_state!
      end

      def ==(other)
        return false unless other.is_a?(self.class)
        other.send(:state) == state && other.send(:index) == index
      end

      def extract
        twist! if index >= n
        temper(state[index])
      ensure
        @index += 1
      end

      def temper(y)
        y ^= (y >> u) & d
        y ^= (y << s) & b
        y ^= (y << t) & c
        y ^= (y >> l)
        lowest_bits(y)
      end

      def untemper(y)
        y = untemper_rshift(y, shift: l)
        y = untemper_lshift(y, shift: t, mask: c)
        y = untemper_lshift(y, shift: s, mask: b)
        untemper_rshift(y, shift: u, mask: d)
      end

      private

      attr_reader(*(PARAMETERS_32.keys))
      attr_accessor :seed, :state, :index

      # General principle:
      #   x ^= (x << y) is periodic.
      #
      # What we want to do, then, is exploit this periodicity:
      #    a -> b -> c -> d
      #    ^              v
      #    |------<-------|
      # Where the temper function went from c -> d, we want to go d->a->b->c to untemper
      # So we do the most naive thing possible, rather than the performant method below which never quite
      # clicked in the ol' brain
      def untemper_lshift(val, shift: , mask: 0xffffffff)
        original = val
        loop do
          prev = val
          val ^= ((val << shift) & mask)
          return prev if val == original
        end
      end

      def untemper_rshift(val, shift: , mask: 0xffffffff)
        original = val
        loop do
          prev = val
          val ^= ((val >> shift) & mask)
          return prev if val == original
        end
      end

      def defunct_untemper_step_for_posterity
        # We're reversing
        #     y ^= (y <<  7) & 0x9d2cf80
        # so, take the bottom 25 bits of y, shift them over, and & that with the constant 0x9d2c5680,
        # and xor the result with the top 25 bits of y.  Notably, this leaves the bottom 7 bits of y
        # untouched.  The general idea is that we iteratively recover bits.  The input shares the bottom 7
        # bits with the proper output.  We work in 7-bit chunks (the last chunk is only 4 bits of course),
        # shifting and xor-ing (and &ing with the appropriate chunk of the mask) as we go.
        #
        # This algorithm never has varying periodicity, unlike the brute force method above.  My current
        # thought is that this is because I'm not appropriately breaking the mask up into chunks like I do
        # here, but I'm not quite sure.  For now, I'll stick with the naive algorithm until I have a complete
        # understanding of this one.
        if debug
          puts " y    #{y.to_bits} #{y}"
          puts
          puts "y<<7  #{((y<<7) & 0xffffffff).to_bits}"
          puts "&with #{(0x00003f80 & b).to_bits}"
          puts "    = #{((y << 7) & (0x00003f80 & b)).to_bits}"
          puts "xor y #{y.to_bits}"
        end

        y ^= (y << 7) & (0x00003f80 & b)

        if debug
          puts "    = #{y.to_bits}"
          puts
          puts "y<<7  #{((y<<7) & 0xffffffff).to_bits}"
          puts "&with #{(0x001fc000 & b).to_bits}"
          puts "    = #{((y << 7) & (0x001fc000 & b)).to_bits}"
          puts "xor y #{y.to_bits}"
        end

        y ^= (y << 7) & (0x001fc000 & b)

        if debug
          puts "    = #{y.to_bits}"
          puts
          puts "y<<7  #{((y<<7) & 0xffffffff).to_bits}"
          puts "&with #{(0x0fe00000 & b).to_bits}"
          puts "    = #{((y << 7) & (0x0fe00000 & b)).to_bits}"
          puts "xor y #{y.to_bits}"
        end

        y ^= (y << 7) & (0x0fe00000 & b)

        if debug
          puts "    = #{y.to_bits}"
          puts
          puts "y<<7  #{((y<<7) & 0xffffffff).to_bits}"
          puts "&with #{(0xf0000000 & b).to_bits}"
          puts "    = #{((y << 7) & (0xf0000000 & b)).to_bits}"
          puts "xor y #{y.to_bits}"
        end

        y ^= (y << 7) & (0xf0000000 & b)

        if debug
          puts "    = #{y.to_bits}"
          puts y
        end
        y
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
