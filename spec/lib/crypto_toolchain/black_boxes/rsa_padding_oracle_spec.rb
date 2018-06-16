require "spec_helper"

RSpec.describe CryptoToolchain::BlackBoxes::RSAPaddingOracle do

  let(:bits) { 256 }
  let(:kp) { CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: bits) }
  let(:oracle) { described_class.new(keypair: kp) }

  it "should return true when a string is pkcs#1 1.5 padded" do
    plains = Array.new(3) { |_| String.random_bytes(10)}
    aggregate_failures do
      plains.each do |plain|
        padded = plain.pad_pkcs1_5(kp.bits)
        ciphertext = kp.encrypt(padded, to: kp.pubkey)
        expect(oracle.execute(ciphertext)).to be true
      end
    end
  end

  it "should return false when a string is not pkcs#1 1.5 padded" do
    plains = [
      "\x00\x02\x00\x01\x01lol",
      "\x01\x02\x00\x01\x01lol",
      "\x01\x02\x00\x01\x01\x01\x01\x01\x01\x01\x01lol",
    ]
    aggregate_failures do
      plains.each do |plain|
        ciphertext = kp.encrypt(plain, to: kp.pubkey)
        expect(oracle.execute(ciphertext)).to be false
      end
    end
  end
end
