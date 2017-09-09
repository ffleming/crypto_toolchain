require "spec_helper"

RSpec.describe CryptoToolchain::Tools::RSABroadcastAttack do
  let(:bits) { 1024 }
  let(:sender) { CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: bits) }
  let(:keypairs) do
    [
      CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: bits),
      CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: bits),
      CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: bits)
    ]
  end
  let(:plain) { "Sometimes poodles like to sleep all day" }
  let(:ciphers) { keypairs.map {|k| sender.encrypt(plain, to: k.public_key).to_number } }

  it "should break RSA given no padding and the same ciphertet encrypted multiple times" do
    pubkeys = keypairs.map(&:public_key)
    inputs = ciphers.zip(pubkeys).map do |c, k|
      CryptoToolchain::Tools::RSABroadcastAttack::Input.new(c, k)
    end
    atk = described_class.new(inputs)
    result = atk.execute
    expect(result).to eq plain
  end
end
