# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::BlackBoxes::MT19937StreamCipher do
  let(:cipher) { CryptoToolchain::BlackBoxes::MT19937StreamCipher.new(plaintext, seed: 150) }
  let(:plaintext) { "Charles is a good dog" }
  let(:ciphertext) { "\xA7\x9C\xF9\x9A\xD6\f\xF8\xCE\x92\x1E*#9\xA7\xFB\xFB\x94!\xCA\x8FU" }
  describe "#encrypt" do
    it "Should encrypt appropriately" do
      expect(cipher.encrypt).to eq ciphertext
    end
  end

  describe "#encrypt" do
    it "Should encrypt appropriately" do
      expect(cipher.decrypt(ciphertext)).to eq plaintext
    end
  end

  context "With a random seed" do
    let(:cipher) { CryptoToolchain::BlackBoxes::MT19937StreamCipher.new(plaintext) }
    it "Should round-trip correctly" do
      ct = cipher.encrypt(plaintext)
      expect(cipher.decrypt(ct)).to eq plaintext
    end
  end

end
