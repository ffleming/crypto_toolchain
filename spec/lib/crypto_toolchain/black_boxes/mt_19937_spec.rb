# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::BlackBoxes::MT19937 do
  # Values from https://gist.github.com/mimoo/8e5d80a2e236b8b6f5ed
  let(:mt32) { CryptoToolchain::BlackBoxes::MT19937.new(1131464071) }
  context "32 bit" do
    it "Should generate the correct values (21)" do
      File.foreach("spec/fixtures/mt32.txt") do |line|
        expect(mt32.extract).to eq line.strip.to_i
      end
    end
  end
end
