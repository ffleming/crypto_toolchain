# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe "Cryptopals Set 1" do
  it "should convert hex to base64 (1)" do
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    expect(hex.from_hex.to_base64).to eq b64
  end

  it "should do fixed xor (2)" do
    str = "1c0111001f010100061a024b53535009181c"
    actual = str.from_hex ^ "686974207468652062756c6c277320657965".from_hex
    expect(actual.to_hex).to eq "746865206b696420646f6e277420706c6179"
  end

  it "should detect a single-byte xor key (3)" do
    bytestring = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".from_hex
    key = CryptoToolchain::Tools.detect_single_character_xor(bytestring)
    expect(key.repeat_to(bytestring.length) ^ bytestring).to eq "Cooking MC's like a pound of bacon"
  end

  it "should detect the single-byte xor encrypted string (4)" do
    winner = File.read("spec/fixtures/1-4.txt").split("\n").map do |hex_str|
      str = hex_str.from_hex
      key = CryptoToolchain::Tools.detect_single_character_xor(str)
      { key: key, plain: key.repeat_to(str.length) ^ str }
    end.sort_by {|h| h[:plain].score}.last
    aggregate_failures do
      expect(winner[:key]).to eq '5'
      expect(winner[:plain]).to eq "Now that the party is jumping\n"
    end
  end

  it "should perform repeating-key xor (5)" do
    input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE".repeat_to(input.bytesize)
    expected =  "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    expect((key ^ input).to_hex).to eq expected
  end

  it "should break repeating-key xor (6)" do
    ciphertext = Base64.decode64(File.read("spec/fixtures/1-6.txt").strip)

    potential_keys = ciphertext.potential_repeating_xor_keys

    result = potential_keys.each_with_object([]) do |key, memo|
      _plain = ciphertext ^ key.repeat_to(ciphertext.bytes.size)
      memo << { score: _plain.score, plain: _plain, key: key }
    end.sort_by { |h| h[:score] }.last

    expect(result[:key]).to eq 'Terminator X: Bring the noise'
    lyric = "Play that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music"
    expect(result[:plain].include? lyric).to be true
  end

  it "should decrypt with AES-128 in ECB mode (7)" do
    ciphertext = File.read("spec/fixtures/1-7.txt").from_base64
    key = "YELLOW SUBMARINE"
    dec = OpenSSL::Cipher::AES.new('128-ECB')
    dec.decrypt
    dec.key = key
    expected = dec.update(ciphertext) + dec.final
    expect(ciphertext.decrypt_ecb(key: key, blocksize: 16)).to eq expected
  end

  it "should encrypt with AES-128 in ECB mode" do
    key = "YELLOW SUBMARINE"
    plain = File.read("spec/fixtures/1-7.txt").from_base64.decrypt_ecb(key: key, blocksize: 16)
    expected = File.read("spec/fixtures/1-7.txt").from_base64
    ciphertext = plain.encrypt_ecb(key: key, blocksize: 16)
    expect(ciphertext.bytes).to eq expected.bytes
  end

  it "should detect ECB mode (8)" do
    most_repeated = File.readlines("spec/fixtures/1-8.txt").map(&:strip).sort_by do |line|
      line.from_hex.unique_blocks(16).size
    end.first
    expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    expect(most_repeated).to eq expected
  end

end

