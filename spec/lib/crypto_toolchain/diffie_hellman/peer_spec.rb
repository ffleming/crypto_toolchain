require 'spec_helper'
RSpec.describe CryptoToolchain::DiffieHellman::Peer do
  let(:msg) { CryptoToolchain::DiffieHellman::Messages }
  let(:a) { CryptoToolchain::DiffieHellman::Peer.new(name: "A",
                                                     p: CryptoToolchain::NIST_P,
                                                     g: CryptoToolchain::NIST_G) }
  let(:b) { CryptoToolchain::DiffieHellman::Peer.new(name: "B", p: nil, g: nil) }

  def begin_processing_for(*peers)
    @peers = peers
    @threads = peers.map do |peer|
      Thread.new { peer.process!  }
    end
  end

  after(:each) do
    sender = @peers.first
    @peers.reverse.each {|p| sender.send_msg(p, msg::Die.new)}
    @threads.each(&:join)
  end

  it "should negotiate a shared secret between two peers" do
    begin_processing_for(a, b)
    b.send_msg(a, msg::PeerAddress.new(peer: b, channel: b.channel, initial: true))
    init_key_exchange = msg::KeyExchange.new(peer: a,
                                             p: a.p,
                                             g: a.g,
                                             pubkey: a.pubkey, initial: true)
    # Processing time for address exchange before we send key exchange, otherwise the
    # peers won't know each others' addresses
    sleep(0.025)
    a.send_msg(b, init_key_exchange)
    sleep(0.025)
    a_secret = a.info_for(b).shared_secret
    b_secret = b.info_for(a).shared_secret
    expect(a_secret).to eq b_secret
    expect(a_secret.nil?).to be false
  end

  it "should send encrypted messages" do
    begin_processing_for(a, b)
    b.send_msg(a, msg::PeerAddress.new(peer: b, channel: b.channel, initial: true))
    init_key_exchange = msg::KeyExchange.new(peer: a,
                                             p: a.p,
                                             g: a.g,
                                             pubkey: a.pubkey, initial: true)
    sleep(0.025)
    a.send_msg(b, init_key_exchange)
    sleep(0.025)
    encrypted = a.encrypted_message_for(b, message: "I like dogs", initial: true)
    a.send_msg(b, encrypted)
    sleep(0.025)
    expect(a.received_messages.map(&:contents)).to eq ["I like dogs"]
  end
end
