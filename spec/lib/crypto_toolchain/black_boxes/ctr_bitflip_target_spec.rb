# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::BlackBoxes::CtrBitflipTarget do
  let(:key) { Random.new.bytes(16) }
  let(:nonce) { rand(0..0x0000ffff) }
  let(:target) { CryptoToolchain::BlackBoxes::CtrBitflipTarget.new(key: key, nonce: nonce) }

  describe "#encrypt" do
    it("should encrypt the string") do
      plain = "comment1=cooking%20MCs;userdata=woof;comment2=%20like%20a%20pound%20of%20bacon"
      expected = plain.encrypt_ctr(key: key, nonce: nonce)
      expect(target.encrypt("woof")).to eq expected
    end
  end

  describe "#is_admin?" do
    it "should not be injectable" do
      inp = target.encrypt(";admin=true;")
      expect(target.is_admin?(inp)).to eq false
    end
  end
end
