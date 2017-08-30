# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe "String extensions" do
  describe "#hamming_distance" do
    it "should get Hamming distance correct" do
      str1 = "this is a test"
      str2 = "wokka wokka!!!"
      aggregate_failures do
        expect(str1.hamming_distance(str2)).to eq 37
        expect(str2.hamming_distance(str1)).to eq 37
      end
    end
  end

  describe "#is_pkcs7_padded?" do
    it "should correctly determine if a block is PKCS7 padded" do
      aggregate_failures do
        (1..15).each do |i|
          str = "#{'A' * (16-i)}#{i.chr * i}"
          expect(str.is_pkcs7_padded?(16)).to be true
        end
      end
    end
  end

  describe "#without_pkcs7_padding" do
    it "should correctly strip PKCS7 padding" do
      aggregate_failures do
        (1..15).each do |i|
          expected = 'A' * (16 - i)
          str = "#{expected}#{i.chr * i}"
          expect(str.without_pkcs7_padding(16)).to eq expected
        end
      end
    end
  end
end
