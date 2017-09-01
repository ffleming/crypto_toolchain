require 'spec_helper'
RSpec.describe CryptoToolchain::DiffieHellman do
  let(:klass) { described_class }
  let(:msg) { klass::Messages }
  let(:a) { CryptoToolchain::DiffieHellman::Peer.new(name: "A") }
  let(:b) { CryptoToolchain::DiffieHellman::Peer.new(name: "B") }

  def begin_processing_for(*peers)
    @peers = peers
    @threads = peers.map do |peer|
      Thread.new { peer.process!  }
    end
  end
  after(:each) do
    sender = @peers.first
    @peers.reverse.each {|p| sender.send_msg(p, msg::Die.new)}
    @threads.map(&:join)
  end

  it "Should negotiate a shared secret between two Peers" do
    begin_processing_for(a, b)
    b.send_msg(a, msg::PeerAddress.new(peer: b, channel: b.channel, initial: true))
    init_key_exchange = msg::KeyExchange.new(peer: a,
                                 p: CryptoToolchain::NIST_P,
                                 g: CryptoToolchain::NIST_G,
                                 pubkey: a.pubkey, initial: true)
    # Processing time for address exchange before we send key exchange, otherwise the
    # peers won't know each others' addresses
    sleep(0.025)
    a.send_msg(b, init_key_exchange)

    a_secret = a.info_for(b).shared_secret
    b_secret = b.info_for(a).shared_secret
    expect(a_secret).to eq b_secret
  end
end
