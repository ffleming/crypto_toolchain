# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe CryptoToolchain::BlackBoxes::AesCtrEditor do
  let(:nonce) { rand(0..0x0000FFFF) }
  let(:key) { Random.new.bytes(16) }
  let(:editor) { CryptoToolchain::BlackBoxes::AesCtrEditor.new(plaintext, key: key, nonce: nonce)}
  let(:plaintext) { "I like dogs, dogs are great.  They like to pilot large airships." }

  describe "#edit" do
    context "Editing the first byte" do
      it "Should edit correctly" do
        actual = editor.edit(offset: 0, with: "I like cats, cat")
        expected_plain =  "I like cats, cats are great.  They like to pilot large airships."
        expected_ciphertext = expected_plain.encrypt_ctr(key: key, nonce: nonce)
        aggregate_failures do
          expect(actual).to eq expected_ciphertext
          expect(actual.decrypt_ctr(key: key, nonce: nonce)). to eq expected_plain
        end
      end
    end

    context "Editing multiple bytes" do
      it "Should edit correctly" do
        actual = editor.edit(offset: 35, with: "hate")
        expected_plain = "I like dogs, dogs are great.  They hate to pilot large airships."
        expected_ciphertext = expected_plain.encrypt_ctr(key: key, nonce: nonce)
        aggregate_failures do
          expect(actual).to eq expected_ciphertext
          expect(actual.decrypt_ctr(key: key, nonce: nonce)). to eq expected_plain
        end
      end
    end
  end
end
