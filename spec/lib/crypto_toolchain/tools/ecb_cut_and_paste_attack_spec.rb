# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::Tools::EcbCutAndPasteAttack do
  it "Should create an admin cookie" do
    oracle = CryptoToolchain::BlackBoxes::EcbCookieEncryptor.new
    attack = CryptoToolchain::Tools::EcbCutAndPasteAttack.new(oracle: oracle)
    profile = oracle.decrypt(attack.execute)
    expect(profile.fetch(:role)).to eq "admin"
  end
end
