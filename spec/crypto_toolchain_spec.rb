require "spec_helper"

describe CryptoToolchain do
  it "has a version number" do
    expect(CryptoToolchain::VERSION).not_to be nil
  end
end
