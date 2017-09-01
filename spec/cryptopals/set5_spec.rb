# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe "Cryptopals Set 5" do
  describe "Diffie-Hellman challenges" do

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

    it "should negotiate a shared secret with DH and use it to encrypt messages (33)" do
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

    it "should perform a man-in-the-middle parameter-injection attack between two peers (34)" do
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
      aggregate_failures do
        expect(mitm.received_messages.map(&:contents)).to eq [plaintext, plaintext]
        expect(mitm.received_messages.map(&:from)).to match_array [a.name, b.name]
        # we've replaced the public key with p so
        #   s = p**n % p
        #   s = 0
        [a, b, mitm].each do |peer|
          peer.addresses do |name, info|
            expect(info.shared_secret).to eq 0
          end
        end
      end
    end
  end
end
