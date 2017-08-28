# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain::Utilities::SHA1 do
  it "should match the output of Digest::SHA1" do
    100.times do
      msg = Random.new.bytes(rand(1..1024))
      expect(CryptoToolchain::Utilities::SHA1.hexdigest(msg)).to eq Digest::SHA1.hexdigest(msg)
    end
  end
end

