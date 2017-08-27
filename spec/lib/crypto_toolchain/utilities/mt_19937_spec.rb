# encoding: ASCII-8BIT
require "spec_helper"
RSpec.describe CryptoToolchain::Utilities::MT19937 do
  context "32 bit" do
    # Values from https://gist.github.com/mimoo/8e5d80a2e236b8b6f5ed
    let(:mt32) { CryptoToolchain::Utilities::MT19937.new(1131464071) }
    describe "#extract" do
      it "Should generate the correct values (21)" do
        File.foreach("spec/fixtures/mt32.txt") do |line|
          expect(mt32.extract).to eq line.strip.to_i
        end
      end
    end

    describe "#untemper" do
      it "Should untemper correctly" do
        ranges = [(0xfffff800..0xffffffff), (0x00000000..0x000008ff)]
        ranges.each do |range|
          range.each do |n|
            tempered = mt32.temper(n)
            expect(mt32.untemper(tempered)).to eq n
          end
        end
      end
    end
  end
end
