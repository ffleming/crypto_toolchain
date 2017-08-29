# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain::Utilities::HMAC do
  context "SHA1" do
    let(:iterations) { 25 }
    let(:messages) do
      iterations.times.with_object([]) do |i, memo|
        memo << Random.new.bytes(rand(1..1024))
      end
    end

    let(:keys) do
      iterations.times.with_object([]) do |i, memo|
        memo << Random.new.bytes(rand(1..128))
      end
    end

    describe "instance methods" do
      describe "#digest" do
        it "should match the output of OpenSSL::HMAC.digest" do
          iterations.times do |i|
            key = keys[i]
            message = messages[i]
            hmac = CryptoToolchain::Utilities::HMAC.new(key: key, hash: CryptoToolchain::Utilities::SHA1)
            expect(hmac.digest(message)).to eq OpenSSL::HMAC.digest('sha1', key, message)
          end
        end
      end

      describe "#hexdigest" do
        it "should match the output of OpenSSL::HMAC.hexdigest" do
          iterations.times do |i|
            key = keys[i]
            message = messages[i]
            hmac = CryptoToolchain::Utilities::HMAC.new(key: key, hash: CryptoToolchain::Utilities::SHA1)
            expect(hmac.hexdigest(message)).to eq OpenSSL::HMAC.hexdigest('sha1', key, message)
          end
        end
      end
    end

    describe "class methods" do
      describe "::digest" do
        it "should match the output of OpenSSL::HMAC.digest" do
          iterations.times do |i|
            key = keys[i]
            message = messages[i]
            actual = CryptoToolchain::Utilities::HMAC.digest(message, key: key, hash: CryptoToolchain::Utilities::SHA1)
            expect(actual).to eq OpenSSL::HMAC.digest('sha1', key, message)
          end
        end
      end
      describe "::hexdigest" do
        it "should match the output of OpenSSL::HMAC.hexdigest" do
          iterations.times do |i|
            key = keys[i]
            message = messages[i]
            actual = CryptoToolchain::Utilities::HMAC.hexdigest(message, key: key, hash: CryptoToolchain::Utilities::SHA1)
            expect(actual).to eq OpenSSL::HMAC.hexdigest('sha1', key, message)
          end
        end
      end
    end
  end
end

