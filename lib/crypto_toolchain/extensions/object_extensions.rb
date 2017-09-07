# encoding: ASCII-8BIT
class Object
  # Transcribed from http://cryptopals.com/sets/5/challenges/40
  def chinese_remainder(residues, mods)
    mod_product = ->(without) { mods.inject(:*) / without }
    sum = 0
    residues.zip(mods) do |(residue, mod)|
      mp = mod_product.call(mod)
      sum += residue * mp * mp.invmod(mod)
    end
    sum % mods.inject(:*)
  end

  def numberize(n)
    if n.respond_to?(:to_number)
      n.to_number
    elsif n.is_a?(Numeric)
      n
    else
      raise ArgumentError, "#{n} cannot be numberized"
    end
  end
end

