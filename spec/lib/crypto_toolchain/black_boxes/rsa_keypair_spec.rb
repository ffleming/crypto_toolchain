require "spec_helper"

RSpec.describe CryptoToolchain::BlackBoxes::RSAKeypair do
  let(:bits) { 512 }
  let(:k1) { described_class.new(bits: bits) }
  let(:k2) { described_class.new(bits: bits) }
  let(:plains) do
    [ "Poodles are cool",
      "Dogs can be cryptographers, too!",
      "A" * 128 ]
  end
  it "should roundtrip successfully within the same keypair" do
    aggregate_failures do
      plains.each do |plain|
        enc = k1.encrypt(plain, to: k1.public_key)
        dec = (k1.decrypt(enc))
        expect(dec).to eq plain
      end
    end
  end

  it "should roundtrip successfully between keypairs" do
    aggregate_failures do
      plains.each do |plain|
        enc = k1.encrypt(plain, to: k2.public_key)
        dec = (k2.decrypt(enc))
        expect(dec).to eq plain
      end
    end
  end
end
