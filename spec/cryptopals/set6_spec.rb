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

    it "should forge an RSA signature when e=3 (42)" do
      plain = "hi mom"
      keypair = CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 512)
      forged = CryptoToolchain::Tools::LowExponentRSASignatureForgery.new(keypair: keypair, message: plain).execute
      expect(keypair.verify(plain, signature: forged)).to be true
    end

    it "should recover a DSA private key when k is generated between 0 and 0x0000ffff (43)" do
      plain = "For those that envy a MC it can be hazardous to your health\n" <<
              "So be friendly, a matter of life and death, just like a etch-a-sketch\n"

      pubkey = "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
                abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
                e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
                1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
                bb283e6633451e535c45513b2d33c99ea17".gsub(/\s/, "").hex

      atk = CryptoToolchain::Tools::DSARecoverPrivateKeyFromNonce.new(public_key: pubkey, message: plain,
                                                                      r: 548099063082341131477253921760299949438196259240,
                                                                      s: 857042759984254168557880549501802188789837994940)
      privkey = atk.execute(min: 16550, max: 16600)
      hsh = CryptoToolchain::Utilities::SHA1.hexdigest(privkey.to_hex)
      expected = "0954edd5e0afe5542a4adf012611a91912a3ec16"
      expect(hsh).to eq expected
    end
  end
end
