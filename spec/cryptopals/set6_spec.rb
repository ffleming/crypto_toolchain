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
      keypair = CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 1024)
      forged = CryptoToolchain::Tools::LowExponentRSASignatureForgery.new(keypair: keypair, message: plain).execute
      expect(keypair.verify(plain, signature: forged)).to be true
    end
  end

  describe "DSA challenges" do
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

    describe "Parameter tampering" do
      let(:plain) { "I like dogs" }
      it "should verify all DSA signatures when g is 0 (45a)" do
        kp = CryptoToolchain::BlackBoxes::DSAKeypair.new(g: 0, dangerous: true)
        r, s = kp.sign(plain)
        expect(kp.verify(plain, r: r, s: s)).to be true
        expect(kp.verify(plain.gsub("dogs", "ducks"), r: r, s: s)).to be true
      end

      it "should generate a 'magic signature' that will verify any string (45b)" do
        kp = CryptoToolchain::BlackBoxes::DSAKeypair.new(g: CryptoToolchain::DSA_P + 1, dangerous: true)
        r, s = kp.sign(plain)
        expect(kp.verify("Hello world", r: r, s: s)).to be true
        expect(kp.verify("Goodbye world", r: r, s: s)).to be true
      end
    end
  end

  describe "RSA oracle attacks" do
    it "should decrypt an RSA ciphertext with a parity oracle (46)" do
      # To complete Cryptopals #46, use the following and increase the size of the RSA keypair to at least 1024
      # "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
      plain = "SSBsaWtlIHBvb2RsZXM=".from_base64
      kp = CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 256)
      ciphertext = kp.encrypt(plain, to: kp.public_key)
      oracle = CryptoToolchain::BlackBoxes::RSAParityOracle.new(kp)
      atk = CryptoToolchain::Tools::RSAParityOracleAttack.new(oracle: oracle, n: kp.public_key.n)
      expect(atk.execute(ciphertext)).to eq plain
    end

    # Used RSA values and a constant string that tend to produce quick recovery
    context "RSA PKCS#1 1.5 padding oracle" do
      it "should recover the message (simple case) (47)" do
        kp = CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 256,
                                                         p: 0xe5f109e2035b672986554a523fdc8883,
                                                         q: 0xe9d2f62dada945e3fea4d1a58ff9b06f)
        plain = "\x00\x02\xFBb\xF7\xB4\x01(\xCF\b,\x95T4\x8Cxm\xBD\xF6*\x00kick it, CC"
        ciphertext = kp.encrypt(plain, to: kp.public_key)
        oracle = CryptoToolchain::BlackBoxes::RSAPaddingOracle.new(keypair: kp)
        atk = CryptoToolchain::Tools::RSAPaddingOracleAttack.new(
          oracle: oracle,
          n: kp.public_key.n,
          e: kp.public_key.e
        )
        expect(atk.execute(ciphertext)).to eq plain
      end

      it "should recover the message (complete case) (48)" do
        p = 0xb08b4c664074144493282a7e7afd6f93a4075fee94783640b1823d5a90940ad4fee936bc5db7df54bb7ea659b7356b87
        q = 0xa9ed40e7d07e20178c69455dec5a27848d6ce5bc98f92853d4d31c53e766dcf2e8d09c07048924490ef673d0469cbd9d
        kp = CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 768, p: p, q: q)
        plain = "\x00\x02#{'a' * 82}\x00kick it, CC"
        ciphertext = kp.encrypt(plain, to: kp.public_key)
        oracle = CryptoToolchain::BlackBoxes::RSAPaddingOracle.new(keypair: kp)
        atk = CryptoToolchain::Tools::RSAPaddingOracleAttack.new(
          oracle: oracle,
          n: kp.public_key.n,
          e: kp.public_key.e
        )
        expect(atk.execute(ciphertext)).to eq plain
      end
    end
  end
end
