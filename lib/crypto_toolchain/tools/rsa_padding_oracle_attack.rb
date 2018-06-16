# encoding: ASCII-8BIT
module CryptoToolchain
  module Tools
    class RSAPaddingOracleAttack
    end
  end
end

class CryptoToolchain::Tools::RSAPaddingOracleAttack
  def initialize(oracle: BlackBoxes::RSAPaddingOracle.new, n: , e: 3)
    @oracle = oracle
    @n = n
    @e = e
  end
  attr_reader :n, :oracle, :e

  def check(int)
    oracle.execute(str_for(int))
  end

  def str_for(int)
    str = int.to_bin_string
    pad = "\x00" * (n.bit_length.updiv(8) - str.bytesize)
    "#{pad}#{str}"
  end

  def execute(ciphertext)
    s = 1
    @c0 = ciphertext.to_number
    intervals = [ [ (2*big_b), (3*big_b ) ] ]
    i = 1
    loop do
      if i == 1
        #2a
        s = start_search()
      elsif intervals.length > 1
        #2b
        s += 1
        s += 1 until check((@c0 * s.modpow(e, n)) % n)
      elsif intervals.length == 1
        #2c
        a, b = intervals.first

        if a == b
          return str_for(a)
        end
        s = search_with_single_interval(a, b, s)
      end

      # 3
      intervals = calculate_intervals(intervals, s)
      i += 1
    end
  end


  def calculate_intervals(intervals, s)
    new_intervals = []
    intervals.each do |a, b|
      min_r = (a * s - 3 * big_b + 1).updiv(n)
      max_r = (b * s - 2 * big_b) / n
      (min_r..max_r).each do |r|
        aa = [a, (2 * big_b + r * n).updiv(s)].max
        bb = [b, ((3 * big_b - 1 + r * n) / s)].min

        new_intervals = add_interval(new_intervals, aa, bb)
      end
    end
    new_intervals
  end

  def add_interval(intervals, lower, upper)
    matched = false
    new_intervals = intervals.map do |a, b|
      if b < lower || a > upper
        # interval to be added does not overlap an existing interval - persist the existing interval
        # if we never overlap an interval, we'll add the [lower, upper] interval later
        [a, b]
      else
        # interval to be added overlaps - extend that interval according to [lower, upper]
        matched = true
        [
          [lower, a].min,
          [upper, b].max
        ]
      end
    end
    if matched
      new_intervals
    else
      new_intervals.push([lower, upper])
    end
  end

  def start_search
    s1 = n.updiv(3 * big_b)
    loop do
      c = (@c0 * s1.modpow(e, n)) % n
      if check(c)
        return s1
      end
      s1 += 1
    end
  end

  def search_with_single_interval(a, b, s)
    r = (2 * (b * s - 2 * big_b)) / (n)
    s = (2 * big_b + r * n) / (b)

    until check((@c0 * s.modpow(e,n)) % n)
      s += 1
      if s > (3 * big_b + r * n) / a
        r += 1
        s = (2 * big_b + r * n) / b
      end
    end
    s
  end

  def big_b
    k = oracle.keypair.bits / 8
    2**(8 * (k - 2))
  end
end
