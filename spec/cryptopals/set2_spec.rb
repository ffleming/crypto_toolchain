# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain do
  it "should perform PCKS#7 padding correctly (9)" do
    key = "YELLOW SUBMARINE"
    expect(key.pad_pkcs7(20)).to eq "YELLOW SUBMARINE\x04\x04\x04\x04"
  end

  it "should perform CBC decryption (10)" do
    ciphertext = File.read("spec/fixtures/2-10.txt").from_base64
    key = "YELLOW SUBMARINE"
    iv = "\x00" * 16
    dec = OpenSSL::Cipher::AES.new('128-CBC')
    dec.decrypt
    dec.key = key
    dec.iv = iv
    expected = dec.update(ciphertext) + dec.final
    actual = ciphertext.decrypt_cbc(key:key,
                                iv: iv,
                                blocksize: 16,
                                cipher: 'AES-128')
    expect(actual).to eq expected
  end

  it "should perform CBC encryption" do
    plain = File.read("spec/fixtures/plain.txt")

    key = "YELLOW SUBMARINE"
    iv = "\x00" * 16
    enc = OpenSSL::Cipher::AES.new('128-CBC')
    enc.encrypt
    enc.key = key
    enc.iv = iv
    enc.padding = 1
    expected = enc.update(plain) + enc.final
    actual = plain.encrypt_cbc(key: key,
                                iv: iv,
                                blocksize: 16,
                                cipher: 'AES-128')
    expect(actual).to eq expected
  end

  it "should correctly determine if EBC or CBC was used (11)" do
    plain = File.read("spec/fixtures/plain.txt")
    cryptor = CryptoToolchain::BlackBoxes::EcbOrCbcEncryptor.new(plain)
    aggregate_failures do
      5.times do
        ciphertext = cryptor.encrypt(:cbc)
        expect(ciphertext.is_ecb_encrypted?(16)).to be false
      end
      5.times do
        ciphertext = cryptor.encrypt(:ecb)
        expect(ciphertext.is_ecb_encrypted?(16)).to be true
      end
    end
  end

  it "should perform simple byte-at-a-time ECB cracking (12)" do
    plaintext = "ABC"
    oracle = CryptoToolchain::BlackBoxes::EcbPrependChosenPlaintextOracle.new
    breaker = CryptoToolchain::Tools::EcbPrependChosenPlaintextAttack.new(oracle.encrypt(plaintext), oracle: oracle)
    expect(breaker.execute).to eq File.read("spec/fixtures/2-12.txt")
  end
end

