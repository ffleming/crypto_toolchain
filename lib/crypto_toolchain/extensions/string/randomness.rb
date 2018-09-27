module CryptoToolchain
  module Extensions
    module String
      module Randomness
      end
    end
  end
end

module CryptoToolchain::Extensions::String::Randomness
  # Not cryptographically secure
  def random_bytes(n)
    n.times.with_object("") do |_, memo|
      memo << random_byte
    end
  end

  # Obviously not cryptographically secure
  def random_byte
    (0..255).to_a.sample.chr
  end
end
