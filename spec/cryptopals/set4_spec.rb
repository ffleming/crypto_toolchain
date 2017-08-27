# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe "Cryptopals Set 4" do
  it "should break 'random access read/write' AES CTR (25)" do
    plain = File.read("spec/fixtures/4-25.txt").from_base64.decrypt_ecb(key: "YELLOW SUBMARINE")
    editor = CryptoToolchain::BlackBoxes::AesCtrEditor.new(plain)
    breaker = CryptoToolchain::Tools::AesCtrRecoverer.new(editor)
    expect(breaker.execute).to eq plain
  end
end
