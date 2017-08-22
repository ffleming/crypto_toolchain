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

  it "Should break fixed-nonce CTR (20)" do
    plains = File.read("spec/fixtures/3-20.txt").split("\n").map(&:strip).map(&:from_base64)
    ctr_key = Random.new.bytes(16)
    nonce = Random.new.bytes(16).unpack("Q<").first
    ciphertexts = plains.map do |pl|
      pl.encrypt_ctr(
        key: ctr_key,
        nonce: nonce,
        blocksize: 16
      )
    end
    shortest_ct_len = ciphertexts.map(&:bytesize).min
    ciphertext = ciphertexts.map {|ct| ct[0...shortest_ct_len]}.join

    key = ciphertext.potential_repeating_xor_keys(potential_keysizes: [shortest_ct_len]).first

    recovered = ciphertext ^ key.repeat_to(ciphertext.bytes.size)
    actual = plains.map {|p| p[0...shortest_ct_len]}.join
    distance = recovered.hamming_distance(actual)
    expect(distance).to be < 200
  end
end

