require "spec_helper"

RSpec.describe CryptoToolchain::Tools::RSAUnpaddedMessageRecoveryAttack do
  let(:bits) { 1024 }
  let(:keypair) { CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: bits) }
  let(:oracle) { CryptoToolchain::BlackBoxes::RSAUnpaddedMessageRecoveryOracle.new(keypair: keypair) }
  let(:atk) { described_class.new(oracle: oracle) }
  it "should work" do
    plains = [ "I hear that poodles make excellent cryptographers", "A+ dog would pet again" ]
    ciphertexts = plains.map {|p| oracle.encrypt(p) }
    recovered = ciphertexts.map do |c|
      atk.execute(c)
    end
    expect(recovered).to eq plains
  end
end
