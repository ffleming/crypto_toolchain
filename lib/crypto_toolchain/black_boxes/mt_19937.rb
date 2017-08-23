#encoding: ASCII-8BIT
module CryptoToolchain
  module BlackBoxes
    class MT19937
      def initialize(seed, **kargs)
        @seed = seed
        set_vars!(defaults.merge(kargs))
        @state = build_state!
      end

      private

      attr_reader(*(defaults.keys))
      attr_reader :seed

      def build_state!
        
      end

      def set_vars!(kargs)
        kargs.each do |k, v|
          instance_variable_set("@#{k}", v)
        end
      end

      def defaults
        {
          w: 32, n: 624, m: 397, r: 31, a: 0x9908b0df, u: 11,
          d: 0xFFFFFFFF, t: 15, c: 0xefc60000, l: 18
        }.freeze
      end

      def f
        @f ||= case w
                 when 32
                   1812433253
                 when 64
                   6364136223846793005
                 else
                   raise ArgumentError.new("Don't know how to generate f for w of #{w}")
                 end
      end
    end
  end
end
