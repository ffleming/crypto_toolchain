# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::BlackBoxes::MT19937StreamCipher do
  let(:cipher) { CryptoToolchain::BlackBoxes::MT19937StreamCipher.new(plaintext, seed: 150) }
  let(:plaintext) { "Charles is a good dog" }
  let(:ciphertext) { "\xA7\xD2\x9Ak\x9CW\x17\xDC\xE7\x16\xB7=\xDA\xFC\x06\x87\x87\xBD\fa\xFB" }
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
