# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe "Integer extensions" do
  describe "#lrot" do
    it "Should perform a rotating left shift" do
      expect(0xdeadbeef.lrot(10)).to eq 0xb6fbbf7a
    end
  end

  describe "#rrot" do
    it "Should perform a rotating right shift" do
      expect(0xb6fbbf7a.rrot(10)).to eq 0xdeadbeef
    end
  end
end
