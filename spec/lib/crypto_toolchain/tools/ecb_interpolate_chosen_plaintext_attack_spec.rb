# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::Tools::EcbInterpolateChosenPlaintextAttack do
  let(:oracle) { CryptoToolchain::BlackBoxes::EcbInterpolateChosenPlaintextOracle.new }

  describe "#execute" do
    it "Should decrypt the string" do
      breaker = CryptoToolchain::Tools::EcbInterpolateChosenPlaintextAttack.new(oracle: oracle)
      expect(breaker.execute).to eq File.read("spec/fixtures/2-12.txt")
    end
  end
end
