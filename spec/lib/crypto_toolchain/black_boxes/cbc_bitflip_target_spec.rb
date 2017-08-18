# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::BlackBoxes::CbcBitflipTarget do
  let(:key) { "\x90" * 16 }
  let(:iv) { "\x00" * 16 }
  let(:target) { CryptoToolchain::BlackBoxes::CbcBitflipTarget.new(key: key, iv: iv)}
  describe "#encrypt" do
    it("should encrypt the string") do
      expected = "\xA99\xE7\x95\x90\xE8r\xA0\xFF\xF4\xA1\x93\x8D\xC1\x11\"" +
        "\r%\xDC\xD84\xA8\xDC\xC9M\t\xAFr`9\f\xD6u\x80\xD4~\xB1\x06)\xA8" +
        "\xCA\xCD\x86\xB8\x87$\xE6.\x01,,\xCE\xA3\xFDx\xEE\xBD\x1E\xEB\xE1" +
        "\xF7\xBF\xA7\xEA\x18\xAC\xD10>\e\xDB6( u\x86\x84\x1C\x15\f"
      expect(target.encrypt("woof")).to eq expected
    end
  end

  describe "#is_admin?" do
    it "should not be injectable" do
      inp = target.encrypt(";admin=true;")
      expect(target.is_admin?(inp)).to eq false
    end
  end

  describe "#self_own" do
    it "should hack itself" do
      expect(target.self_own).to be true
    end
  end
end
