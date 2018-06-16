# encoding: ASCII-8BIT
require 'spec_helper'
require 'time'

RSpec.describe CryptoToolchain::Tools::RSAPaddingOracleAttack do
  describe "Simple case" do
    context "When the calculations yield a single interval" do
      it "should recover the message" do
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
    end

    context "When the calculations yields many intervals", slow: true do
      it "should recover the message" do
        kp = CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 256,
                                                         p: 0xdf46d7d3c25fab3e3f2d58dfbe54dbdb,
                                                         q: 0xdfdc6e013eb68ccd98088c8779efcec3)
        plain = "\x00\x02*\xDA\xF0\xE63\b\x1C\xC1$\xC7\x99w\xA3\x19\xB4Y\x93\xEC\x00kick it, CC"
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

  describe "Complete case" do
    context "When calculations yield a single interval" do
      it "should recover the message" do
        p = 0xfdc4e071630ca19d318150e6c8756d1173cb0784108dc0d10872f6e9c7f27cdd0dcb4a46925c712540ba63276560131b
        q = 0xdc966b69a79b63e06295d72a12e16151bcf649ee3a2902aa7ce729036f6c02c867564a97eed7303cd8de1a203e62d9d3
        kp = CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 768, p: p, q: q)
        plain = "\x00\x02\xC3%\x1D\r\xF0G\xF6\v;\xC2l\xF0\xDE\xD9\x84\x7F\xDB\x17\xF0_\x8A\xDD$\t\x89\xB0\xE9\xD1M\x9B\xF0\e\xEC\". JNy48\xCD\xD5\xE1\x0F\x98\xF2]\xFAO\"\xD0AGw\x90\x0F\xCA\x10-\xFC\xC9\xE5q\xF0\x17S\xCA\xEDH\x89_\x90\xB8\x86\x192\xD3L\xF8\x96A\x00kick it, CC"
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

    context "When the calculations yield multiple intervals", slow: true do
      it "should recover the message" do
        p = 0xf9b6f9d95478eb25dc662ff23bf9669c68aa322ae5dee7f70a31dcf5bbf938824fbfa8a5b245b6a99ea513167374e98f
        q = 0xf6f8a8818e8ded22461b1b15be3abfe5df17de8178ee5de76e8a865e7d488a49e6157d313fc4079497dfbdc100ee149b
        kp = CryptoToolchain::BlackBoxes::RSAKeypair.new(bits: 768, p: p, q: q)
        plain = "\x00\x02\xC8\xEF\a\x9Dg\x11\xA0\xF6\xC8\r\nD_\xBC\xB1\xA3\xD75n\xB4^\xB6\xDB9zr\xE3t\xBFq\x13\x17Q\xA0@\xFF\xD8?\x92\xFF\xE8\xA2\xA5\xCC\xD0\xB0\x946}|\xB4\x9F\xDF\xD7\xBC\xE2\xBC\xE9\x87A\xBB\xB4\xAB\xCA\xF2?K$\x18\x15joyd\xEA\x95\f\x13K\xB3\x87y\x00kick it, CC"
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
