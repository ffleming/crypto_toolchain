# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe "Cryptopals Set 3" do
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

  it "Should implement MT-19937 (21)" do
    mt32 = CryptoToolchain::BlackBoxes::MT19937.new(1131464071)
    File.foreach("spec/fixtures/mt32.txt") do |line|
      expect(mt32.extract).to eq line.strip.to_i
    end
  end

  it "Should find the seed of MT-19937 given the first output (22)" do
    seed = Time.now.to_i - rand(40..1000)
    mt = CryptoToolchain::BlackBoxes::MT19937.new(seed)
    val = mt.extract
    recovered = CryptoToolchain::Tools::MT19937SeedRecoverer.new(val).execute
    expect(recovered).to eq seed
  end
end

