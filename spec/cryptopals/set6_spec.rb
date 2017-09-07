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

    it "should recover a DSA nonce from messages signed with a repeated nonce, and then recover the private key (44)" do
      pubkey = ("2d026f4bf30195ede3a088da85e398ef869611d0f68f07" <<
                "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8" <<
                "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519" <<
                "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430" <<
                "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3" <<
                "2971c3de5084cce04a2e147821").hex

      inputs = File.read("spec/fixtures/6-44.txt").split("\n").each_slice(4).map do |msg_arr|
        CryptoToolchain::Tools::DSARecoverNonceFromSignatures::Input.new(
          message: msg_arr[0][5..-1],
          s: msg_arr[1][3..-1],
          r: msg_arr[2][3..-1]
        )
      end

      atk = CryptoToolchain::Tools::DSARecoverNonceFromSignatures.new(inputs)
      expected = 1463790875927859842403284749733079007020529705323315338331058393974134914205120675274591705642504
      k = atk.execute
      expect(k).to eq expected

      r = atk.targets.first.r
      s = atk.targets.first.s
      message = atk.targets.first.message
      rec = CryptoToolchain::Tools::DSARecoverPrivateKeyFromNonce.new(r: r, s: s, message: message,
                                                                      public_key: pubkey)

      privkey = rec.private_key_from(k: k)
      expect(Digest::SHA1.hexdigest(privkey.to_hex)).to eq "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    end
  end
end
