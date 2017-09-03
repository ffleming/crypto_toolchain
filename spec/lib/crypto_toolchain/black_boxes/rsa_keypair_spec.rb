require "spec_helper"

RSpec.describe CryptoToolchain::BlackBoxes::RSAKeypair do
  let(:bits) { 256 }
  let(:k1) { described_class.new(bits: bits) }
  let(:k2) { described_class.new(bits: bits) }
  let(:plain) { "Poodles are cool" }

  it "should roundtrip successfully within the same keypair" do
    enc = k1.encrypt(plain, to: k1.public_key)
    dec = (k1.decrypt(enc))
    expect(dec).to eq plain
  end

  it "should roundtrip successfully between keypairs" do
    enc = k1.encrypt(plain, to: k2.public_key)
    dec = (k2.decrypt(enc))
    expect(dec).to eq plain
  end
end
