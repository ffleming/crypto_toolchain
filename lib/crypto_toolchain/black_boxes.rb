require "crypto_toolchain/black_boxes/ecb_or_cbc_encryptor"
require "crypto_toolchain/black_boxes/ecb_prepend_chosen_plaintext_oracle"
require "crypto_toolchain/black_boxes/ecb_interpolate_chosen_plaintext_oracle"
require "crypto_toolchain/black_boxes/ecb_cut_and_paste_target"
require "crypto_toolchain/black_boxes/cbc_bitflip_target"
require "crypto_toolchain/black_boxes/cbc_padding_oracle"
require "crypto_toolchain/black_boxes/netcat_cbc_padding_oracle"
require "crypto_toolchain/black_boxes/mt_19937_stream_cipher"
require "crypto_toolchain/black_boxes/aes_ctr_editor"
require "crypto_toolchain/black_boxes/ctr_bitflip_target"
require "crypto_toolchain/black_boxes/cbc_iv_equals_key_target"
require "crypto_toolchain/black_boxes/sha1_mac"
require "crypto_toolchain/black_boxes/md4_mac"
require "crypto_toolchain/black_boxes/rsa_keypair"
require "crypto_toolchain/black_boxes/rsa_unpadded_message_recovery_oracle"
require "crypto_toolchain/black_boxes/rsa_parity_oracle"
require "crypto_toolchain/black_boxes/dsa_keypair"
require "crypto_toolchain/black_boxes/rsa_padding_oracle"

module CryptoToolchain
  module BlackBoxes
  end
end
