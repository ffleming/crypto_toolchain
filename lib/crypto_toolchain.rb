require "base64"
require "pry-byebug"
require "pp"
require "uri"
require 'json'
require "crypto_toolchain/version"
require "crypto_toolchain/string_utils"
require "crypto_toolchain/tools"
require "crypto_toolchain/tools/determine_blocksize"
require "crypto_toolchain/tools/ecb_prepend_chosen_plaintext_attack"
require "crypto_toolchain/tools/ecb_interpolate_chosen_plaintext_attack"
require "crypto_toolchain/tools/ecb_cut_and_paste_attack"
require "crypto_toolchain/tools/cbc_bitflip_attack"
require "crypto_toolchain/tools/cbc_padding_oracle_attack"
require "crypto_toolchain/tools/interactive_xor"
require "crypto_toolchain/tools/mt_19937_seed_recoverer"
require "crypto_toolchain/tools/aes_ctr_recoverer"

require "crypto_toolchain/black_boxes/aes_ctr_editor"
require "crypto_toolchain/black_boxes/ecb_or_cbc_encryptor"
require "crypto_toolchain/black_boxes/ecb_prepend_chosen_plaintext_oracle"
require "crypto_toolchain/black_boxes/ecb_interpolate_chosen_plaintext_oracle"
require "crypto_toolchain/black_boxes/ecb_cut_and_paste_target"
require "crypto_toolchain/black_boxes/cbc_bitflip_target"
require "crypto_toolchain/black_boxes/cbc_padding_oracle"
require "crypto_toolchain/black_boxes/netcat_cbc_padding_oracle"
require "crypto_toolchain/black_boxes/mt_19937"
require "crypto_toolchain/black_boxes/mt_19937_stream_cipher"
require "crypto_toolchain/black_boxes/aes_ctr_editor"

module CryptoToolchain
  AES_BLOCK_SIZE = 16
end
