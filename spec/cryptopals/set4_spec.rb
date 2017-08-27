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
end
