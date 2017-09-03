# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe "Cryptopals Set 6" do
  describe "RSA challenges" do
    let(:bits) { 512 }
    let(:keypair) { CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: bits) }
    let(:plain) { "I hear that poodles make excellent cryptographers" }

    it "should recover the plaintext given a decryption oracle and a ciphertext (41)" do
      oracle = CryptoToolchain::BlackBoxes::RSAUnpaddedMessageRecoveryOracle.new(keypair: keypair)
      atk = CryptoToolchain::Tools::RSAUnpaddedMessageRecoveryAttack.new(oracle: oracle)
      ciphertext = oracle.encrypt(plain)
      recovered = atk.execute(ciphertext)
      expect(recovered).to eq plain
    end
  end
end
