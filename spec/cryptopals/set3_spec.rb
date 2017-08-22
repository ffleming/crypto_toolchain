# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain do
  it "Should crack CBC when a padding oracle is available (17)" do
    oracle = CryptoToolchain::BlackBoxes::CbcPaddingOracle.new
    atk = CryptoToolchain::Tools::CbcPaddingOracleAttack.new(oracle: oracle)
    expect(atk.execute).to eq oracle.plaintext[16..-1]
  end

  it "Should encrypt/decrypt CTR mode AES (18)" do
    ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".from_base64
    plaintext = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    aggregate_failures do
      expect(ciphertext.decrypt_ctr(nonce: 0, key: "YELLOW SUBMARINE", blocksize: 16)).to eq plaintext
      expect(plaintext.encrypt_ctr(nonce: 0, key: "YELLOW SUBMARINE", blocksize: 16)).to eq ciphertext
    end
  end
end

