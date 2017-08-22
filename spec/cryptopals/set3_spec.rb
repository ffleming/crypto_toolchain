# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain do
  it "Should crack CBC when a padding oracle is available (17)" do
    oracle = CryptoToolchain::BlackBoxes::CbcPaddingOracle.new
    atk = CryptoToolchain::Tools::CbcPaddingOracleAttack.new(oracle: oracle)
    expect(atk.execute).to eq oracle.plaintext[16..-1]
  end
end

