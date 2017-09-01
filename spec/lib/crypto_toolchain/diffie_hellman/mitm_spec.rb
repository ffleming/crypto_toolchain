require 'spec_helper'
RSpec.describe CryptoToolchain::DiffieHellman::MITM do
  let(:msg) { CryptoToolchain::DiffieHellman::Messages }
  let(:a) { CryptoToolchain::DiffieHellman::Peer.new(name: "A",
                                                     p: CryptoToolchain::NIST_P,
                                                     g: CryptoToolchain::NIST_G) }
  let(:b) { CryptoToolchain::DiffieHellman::Peer.new(name: "B", p: nil, g: nil) }
  let(:mitm) { CryptoToolchain::DiffieHellman::MITM.new(name: "MITM",
                                                        peer_a: a,
                                                        peer_b: b) }


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

  it "should perform a parameter-injection attack between two peers" do
    begin_processing_for(mitm, b, a)
    a.send_msg(mitm, msg::PeerAddress.new(peer: a, channel: a.channel, initial: true))
    # Processing time for address exchange before we send key exchange, otherwise the
    # peers won't know each others' addresses
    sleep(0.025)

    init_key_exchange_from_a = msg::KeyExchange.new(peer: a,
                                                    p: a.p,
                                                    g: a.g,
                                                    pubkey: a.pubkey, initial: true)

    a.send_msg(mitm, init_key_exchange_from_a)
    sleep(0.025)
    plaintext = "I like dogs"
    encrypted = a.encrypted_message_for(mitm, message: plaintext, initial: true)
    a.send_msg(mitm, encrypted)

    sleep(0.025)
    expect(mitm.received_messages.map(&:contents)).to eq [plaintext, plaintext]
    expect(mitm.received_messages.map(&:from)).to match_array [a.name, b.name]
  end
end

