# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain::Tools::SHA1LengthExtensionAttack do
  it "should perform a SHA1 key extension attack" do
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
end
