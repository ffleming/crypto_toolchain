require "crypto_toolchain/tools/determine_blocksize"
require "crypto_toolchain/tools/ecb_prepend_chosen_plaintext_attack"
require "crypto_toolchain/tools/ecb_interpolate_chosen_plaintext_attack"
require "crypto_toolchain/tools/ecb_cut_and_paste_attack"
require "crypto_toolchain/tools/cbc_bitflip_attack"
require "crypto_toolchain/tools/cbc_padding_oracle_attack"
require "crypto_toolchain/tools/interactive_xor"
require "crypto_toolchain/tools/mt_19937_seed_recoverer"
require "crypto_toolchain/tools/mt_19937_stream_cipher_seed_recoverer"
require "crypto_toolchain/tools/aes_ctr_recoverer"

module CryptoToolchain
  module Tools
    PRINTABLE_CHARS = ((0x20..0x7e).to_a + [0x0a, 0x0d]).map(&:chr).freeze
    def self.detect_single_character_xor(bytestring, non_printable: true)
      range = non_printable ? (0..255) : PRINTABLE_CHARS
      range.map(&:chr).sort_by do |chr|
        (chr.repeat_to(bytestring.length) ^ bytestring).score
      end.last
    end
  end
end
