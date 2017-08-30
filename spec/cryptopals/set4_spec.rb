# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe "Cryptopals Set 4" do
  it "should break 'random access read/write' AES CTR (25)" do
    plain = File.read("spec/fixtures/4-25.txt").from_base64.decrypt_ecb(key: "YELLOW SUBMARINE")
    editor = CryptoToolchain::BlackBoxes::AesCtrEditor.new(plain)
    breaker = CryptoToolchain::Tools::AesCtrRecoverer.new(editor)
    expect(breaker.execute).to eq plain
  end

  it "should perform a CTR bitflip attack (26)" do
    target = CryptoToolchain::BlackBoxes::CtrBitflipTarget.new
    mal = CryptoToolchain::Tools::CtrBitflipAttack.new(target: target).execute
    expect(target.is_admin?(mal)).to be true
  end

  it "it should reveal the key when key=iv in CBC mode provided an error message information leak (27)" do
    target = CryptoToolchain::BlackBoxes::CbcIvEqualsKeyTarget.new
    key = CryptoToolchain::Tools::CbcIvEqualsKeyAttack.new(target: target).execute
    expect(key).to eq target.send(:key)
  end

  it "should produce a SHA1 MAC (28)" do
    sha1 = CryptoToolchain::BlackBoxes::SHA1Mac.new(key: "woof")
    mac = sha1.mac("Dogs are cool")
    expect(mac).to eq CryptoToolchain::Utilities::SHA1.hexdigest("woofDogs are cool")
  end

  it "should perform a SHA1 length extension attack (29)" do
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    add = ";admin=true"
    validator = CryptoToolchain::BlackBoxes::SHA1Mac.new
    mac = validator.mac(message)

    found = false
    (1..32).each do |key_len|
      atk = CryptoToolchain::Tools::SHA1LengthExtensionAttack.new(message: message,
                                                                  mac: mac,
                                                                  add: add,
                                                                  key_length: key_len)
      forged_message, forged_mac = atk.execute
      found ^= validator.valid?(message: forged_message, mac: forged_mac)
    end
    expect(found).to be true
  end

  it "should perform a MD4 length extension attack (30)" do
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    add = ";admin=true"
    validator = CryptoToolchain::BlackBoxes::MD4Mac.new
    mac = validator.mac(message)

    found = false
    (1..32).each do |key_len|
      atk = CryptoToolchain::Tools::MD4LengthExtensionAttack.new(message: message,
                                                                  mac: mac,
                                                                  add: add,
                                                                  key_length: key_len)
      forged_message, forged_mac = atk.execute
      found ^= validator.valid?(message: forged_message, mac: forged_mac)
    end
    expect(found).to be true
  end

  it "should implement HMAC-SHA1 (30a)" do
    10.times do |i|
      key = Random.new.bytes(rand(1..128))
      message = Random.new.bytes(rand(1..1024))
      actual = CryptoToolchain::Utilities::HMAC.hexdigest(message, key: key, hash: CryptoToolchain::Utilities::SHA1)
      expect(actual).to eq OpenSSL::HMAC.hexdigest('sha1', key, message)
    end
  end
end
