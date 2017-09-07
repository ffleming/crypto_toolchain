require "spec_helper"

RSpec.describe CryptoToolchain::Tools::DSARecoverNonceFromSignatures do
  it "should recover the DSA nonce from messages signed with the same nonce" do
    pubkey = ("2d026f4bf30195ede3a088da85e398ef869611d0f68f07" <<
              "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8" <<
              "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519" <<
              "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430" <<
              "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3" << 
              "2971c3de5084cce04a2e147821").hex
    inputs = File.read("spec/fixtures/6-44.txt").split("\n").each_slice(4).map do |msg_arr|
      described_class::Input.new(
        message: msg_arr[0][5..-1],
        s: msg_arr[1][3..-1],
        r: msg_arr[2][3..-1]
      )
    end

    atk = described_class.new(inputs)
    expected = 1463790875927859842403284749733079007020529705323315338331058393974134914205120675274591705642504
    k = atk.execute
    expect(k).to eq expected

    r = atk.targets.first.r
    s = atk.targets.first.s
    message = atk.targets.first.message
    rec = CryptoToolchain::Tools::DSARecoverPrivateKeyFromNonce.new(r: r, s: s, message: message,
                                                                    public_key: pubkey)
    privkey = rec.private_key_from(k: k)
    expect(Digest::SHA1.hexdigest(privkey.to_hex)).to eq "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
  end
end
