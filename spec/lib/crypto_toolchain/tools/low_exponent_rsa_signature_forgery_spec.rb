# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::Tools::LowExponentRSASignatureForgery do
  it "should work" do
    plain = "hi mom"
    keypair = CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 512)
    sig = keypair.sign(plain)

    forged = CryptoToolchain::Tools::LowExponentRSASignatureForgery.new(keypair: keypair, message: plain).execute

    aggregate_failures do
      expect(keypair.verify(plain, signature: sig)).to be true
      expect(keypair.verify(plain, signature: forged)).to be true
    end
  end
end

