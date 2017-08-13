module CryptoToolchain
  module Tools
    PRINTABLE_CHARS = (' '..'~')
    def self.detect_single_character_xor(bytestring, non_printable: true)
      range = non_printable ? (0..255) : PRINTABLE_CHARS
      range.map(&:chr).sort_by do |chr|
        (chr.repeat_to(bytestring.length) ^ bytestring).score
      end.last
    end
  end
end
