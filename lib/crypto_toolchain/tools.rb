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
require "crypto_toolchain/tools/ctr_bitflip_attack"
require "crypto_toolchain/tools/cbc_iv_equals_key_attack"
require "crypto_toolchain/tools/sha1_length_extension_attack"
require "crypto_toolchain/tools/md4_length_extension_attack"
require "crypto_toolchain/tools/rsa_broadcast_attack"
require "crypto_toolchain/tools/rsa_unpadded_message_recovery_attack"
require "crypto_toolchain/tools/low_exponent_rsa_signature_forgery"
require "crypto_toolchain/tools/dsa_recover_private_key_from_nonce"
require "crypto_toolchain/tools/dsa_recover_nonce_from_signatures"
require "crypto_toolchain/tools/rsa_parity_oracle_attack"
require "crypto_toolchain/tools/rsa_padding_oracle_attack"

module CryptoToolchain
  module Tools
    def self.detect_single_character_xor(bytestring, non_printable: true)
      arr = non_printable ? (0..255).map(&:chr).to_a : CryptoToolchain::PRINTABLE_CHARACTERS
      arr.sort_by do |chr|
        (chr.repeat_to(bytestring.length) ^ bytestring).score
      end.last
    end
  end
end
