# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain::Tools::MT19937StreamCipherSeedRecoverer do
  let(:random) { Random.new.bytes(rand(0..255)) }
  let(:known) { "Poodles are good dogs" }
  let(:stream) { CryptoToolchain::BlackBoxes::MT19937StreamCipher.new(random + known) }
  let(:ciphertext) { stream.encrypt }
  let(:recover) do
    CryptoToolchain::Tools::MT19937StreamCipherSeedRecoverer.new(ciphertext: ciphertext, known: known)
  end
  let(:recovered_seed) { recover.execute }

  before(:each) do
    CryptoToolchain::BlackBoxes::MT19937StreamCipher.max_seed = 0x000000ff
  end

  describe "#execute" do
    it "Should recover the seed" do
      expect(recovered_seed).to eq(stream.send(:seed))
    end
  end

  describe "::recover_from" do
    it "Should recover the plaintext given ciphertext and a seed" do
      recovered = recover.class.recover_from(seed: recovered_seed, ciphertext: ciphertext)
      expect(recovered).to eq(random + known)
    end
  end

  describe "::vaid_token?" do
    let(:token) { CryptoToolchain::BlackBoxes::MT19937StreamCipher.generate_token }
    it "Should correctly validate real tokens" do
      expect(recover.class.valid_token?(token)).to be true
    end

    it "Should not validate fake tokens" do
      expect(recover.class.valid_token?(Random.new.bytes(16))).to be false
    end
  end
end
