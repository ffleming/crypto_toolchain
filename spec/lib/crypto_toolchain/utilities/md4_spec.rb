# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain::Utilities::MD4 do
  it "should match the output of OpenSSL::Digest::MD4" do
    100.times do
      msg = Random.new.bytes(rand(1..1024))
      expect(CryptoToolchain::Utilities::MD4.hexdigest(msg)).to eq OpenSSL::Digest::MD4.hexdigest(msg)
    end
  end
end

