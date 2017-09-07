require "spec_helper"

RSpec.describe CryptoToolchain::BlackBoxes::DSAKeypair do
  let(:plain) do
    "For those that envy a MC it can be hazardous to your health\n" <<
    "So be friendly, a matter of life and death, just like a etch-a-sketch\n"
  end
  let(:kp) { described_class.new }

  describe "#sign , #verify" do
    it "should sign and verify a message" do
      r, s = kp.sign(plain)
      expect(kp.verify(plain, r: r, s: s)).to be true
    end

    it "should fail to verify on tampered messages" do
      r, s = kp.sign(plain)
      expect(kp.verify("Dogs are cool", r: r, s: s)).to be false
    end
  end
end
