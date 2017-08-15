# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::Tools::EcbPrependChosenPlaintextAttack do
  let(:plaintext) { File.read("spec/fixtures/plain.txt") }
  let(:oracle) { CryptoToolchain::BlackBoxes::EcbPrependChosenPlaintextOracle.new }
  describe "#blocksize" do
    it "should correctly determine blocksize" do
      breaker = CryptoToolchain::Tools::EcbPrependChosenPlaintextAttack.new(oracle.encrypt(plaintext), oracle: oracle)
      expect(breaker.blocksize).to eq 16
    end
  end

  describe "#execute" do
    it "Should decrypt the string" do
      breaker = CryptoToolchain::Tools::EcbPrependChosenPlaintextAttack.new(oracle.encrypt(plaintext), oracle: oracle)
      expect(breaker.execute).to eq File.read("spec/fixtures/2-12.txt")
    end
  end
end
