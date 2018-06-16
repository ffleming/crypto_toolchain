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

  describe "#pad_pkcs1_5" do
    it "should correclty apply PKCS#1v1.5 padding" do
      plain = "woof bark arf wooooooooooo bow wow"
      actual = plain.pad_pkcs1_5(1024)
      aggregate_failures do
        expect(actual.length).to eq (1024 / 8)
        expect(actual[0..1]).to eq "\x00\x02"
        substr = actual[-(plain.length + 1)..-1]
        expect(substr).to eq "\x00#{plain}"
      end
    end

    it "should raise when the string is too long" do
      expect { ("A" * 118).pad_pkcs1_5(1024) }.to raise_error(ArgumentError)
    end
  end

  describe "#is_pkcs1_5_padded?" do
    let(:good) do
      [
        "\x00\x02#{0xff.chr * 8}\x00AAAAAAAAAAAAAAAAAAAAA",
        "\x00\x02#{0xff.chr * 26}\x00AAA",
        "\x00\x02#{0xff.chr * 28}\x00A"
      ]
    end
    let(:bad) do
      [
        "A", good.first.gsub("\x00", "\x01"),
        good.first[1..-1]
      ]
    end
    it "should report correctly" do
      aggregate_failures do
        good.each {|str| expect(str.is_pkcs1_5_padded?(256)).to be true }
        bad.each {|str| expect(str.is_pkcs1_5_padded?(256)).to be false }
      end
    end
  end
end
