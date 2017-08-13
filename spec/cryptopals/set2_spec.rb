# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain do
  it "Should perform PCKS#7 padding correctly (9)" do
    key = "YELLOW SUBMARINE"
    expect(key.pad_pkcs7(20)).to eq "YELLOW SUBMARINE\x04\x04\x04\x04"
  end

  it "Should perform CBC decryption (10)" do
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
end

