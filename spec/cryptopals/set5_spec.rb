# encoding: ASCII-8BIT
require "spec_helper"

RSpec.describe "Cryptopals Set 5" do
  describe "Diffie-Hellman challenges" do

    let(:msg) { CryptoToolchain::DiffieHellman::Messages }
    let(:a) { CryptoToolchain::DiffieHellman::Peer.new(name: "A",
                                                       p: CryptoToolchain::NIST_P,
                                                       g: CryptoToolchain::NIST_G) }
    let(:b) { CryptoToolchain::DiffieHellman::Peer.new(name: "B", p: nil, g: nil) }
    let(:p) { CryptoToolchain::NIST_P }

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
      mitm =  CryptoToolchain::DiffieHellman::MITM.new(name: "MITM",
                                                       peer_a: a,
                                                       peer_b: b,
                                                       p: p,
                                                       pubkey: p)
      begin_processing_for(mitm, b, a)
      a.send_msg(mitm, msg::PeerAddress.new(peer: a, channel: a.channel, initial: true))
      # Processing time for address exchange before we send key exchange, otherwise the
      # peers won't know each others' addresses
      sleep(0.025)

      mitm.do_key_exchange
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

    it "should set the shared secret to 1 (35a)" do
      mitm = CryptoToolchain::DiffieHellman::MITM.new(name: "MITM",
                                                      peer_a: a,
                                                      peer_b: b,
                                                      p: p,
                                                      g: 1)
      begin_processing_for(mitm, b, a)
      mitm.send_msg(a, msg::PeerAddress.new(peer: mitm, channel: mitm.channel, initial: true))
      mitm.send_msg(b, msg::PeerAddress.new(peer: mitm, channel: mitm.channel, initial: true))
      # Processing time for address exchange before we send key exchange, otherwise the
      # peers won't know each others' addresses
      sleep(0.025)

      mitm.do_key_exchange
      sleep(0.025)
      plaintext = "I like dogs"
      encrypted = a.encrypted_message_for(mitm, message: plaintext, initial: true)
      a.send_msg(mitm, encrypted)

      sleep(0.025)
      aggregate_failures do
        expect(mitm.received_messages.map(&:contents)).to eq [plaintext, plaintext]
        expect(mitm.received_messages.map(&:from)).to match_array [a.name, b.name]
        # we've replaced g with 1 so
        #   pubkey = 1**privkey % p
        #          = 1
        #   secret = 1**privkey % p
        #          = 1
        [a, b, mitm].each do |peer|
          peer.addresses.each do |_, info|
            expect(info.shared_secret).to eq 1
          end
        end
      end
    end

    it "should set the shared secret to 0 (35b)" do
      mitm = CryptoToolchain::DiffieHellman::MITM.new(name: "MITM",
                                                      peer_a: a,
                                                      peer_b: b,
                                                      p: p,
                                                      g: p)

      begin_processing_for(mitm, b, a)
      mitm.send_msg(a, msg::PeerAddress.new(peer: mitm, channel: mitm.channel, initial: true))
      mitm.send_msg(b, msg::PeerAddress.new(peer: mitm, channel: mitm.channel, initial: true))
      # Processing time for address exchange before we send key exchange, otherwise the
      # peers won't know each others' addresses
      sleep(0.025)

      mitm.do_key_exchange
      sleep(0.025)
      plaintext = "I like dogs"
      encrypted = a.encrypted_message_for(mitm, message: plaintext, initial: true)
      a.send_msg(mitm, encrypted)

      sleep(0.025)
      aggregate_failures do
        expect(mitm.received_messages.map(&:contents)).to eq [plaintext, plaintext]
        expect(mitm.received_messages.map(&:from)).to match_array [a.name, b.name]
        # we've replaced g with p so
        #   pubkey = p**privkey % p
        #          = 0
        #   secret = 0**privkey % p
        #          = 0
        [a, b, mitm].each do |peer|
          peer.addresses.each do |_, info|
            expect(info.shared_secret).to eq 0
          end
        end
      end
    end


    it "should set the shared secret to 1 (35c)" do
      mitm = CryptoToolchain::DiffieHellman::MITM.new(name: "MITM",
                                                      peer_a: a,
                                                      peer_b: b,
                                                      p: p,
                                                      g: p-1)

      begin_processing_for(mitm, b, a)
      mitm.send_msg(a, msg::PeerAddress.new(peer: mitm, channel: mitm.channel, initial: true))
      mitm.send_msg(b, msg::PeerAddress.new(peer: mitm, channel: mitm.channel, initial: true))

      sleep(0.025)

      mitm.do_key_exchange
      sleep(0.050)
      plaintext = "I like dogs"
      encrypted = a.encrypted_message_for(mitm, message: plaintext, initial: true)
      a.send_msg(mitm, encrypted)

      sleep(0.025)
      aggregate_failures do
        expect(mitm.received_messages.map(&:contents)).to eq [plaintext, plaintext]
        expect(mitm.received_messages.map(&:from)).to match_array [a.name, b.name]
        # we've replaced g with p so
        #   pubkey = p-1**privkey % p
        #          = 1 OR (p-1) depending on if privkey is odd or even
        #   secret = (1 or p-1)**privkey % p
        #          = 1 OR (p-1)
        expected = [p-1, 1]
        [a, b, mitm].each do |peer|
          peer.addresses.each do |_, info|
            expect(expected).to include(info.shared_secret)
          end
        end
      end
    end
  end

  describe "SRP challenges" do
    def start_threading(*instances)
      @threads = instances.map do |p|
        Thread.new { p.go! }
      end
    end

    let(:sockets) { UNIXSocket.pair }
    let(:s1) { sockets.first }
    let(:s2) { sockets.last }
    let(:server) { CryptoToolchain::SRP::Server.new(socket: s2) }

    after(:each) { @threads.each(&:join) }

    it "should negotiate a shared secret and authenticate (36)" do
      client = CryptoToolchain::SRP::Client.new(socket: s1)
      start_threading(client, server)
      client.send_hello
      sleep(0.25)

      expect(client.key).to eq server.key
      expect(client.authenticated?).to be true
    end

    it "should be able to bypass authentication by setting its pubkey to 0 (37a)" do
      client = CryptoToolchain::SRP::Client.new(socket: s1, pubkey: 0)
      start_threading(client, server)
      client.send_hello
      sleep(0.25)

      expect(server.key).to eq Digest::SHA256.hexdigest("0")
      expect(client.authenticated?).to be true
    end

    it "should be able to bypass authentication by setting its pubkey to N (37b)" do
      client = CryptoToolchain::SRP::Client.new(socket: s1, pubkey: CryptoToolchain::NIST_P)
      start_threading(client, server)
      client.send_hello
      sleep(0.25)

      expect(server.key).to eq Digest::SHA256.hexdigest("0")
      expect(client.authenticated?).to be true
    end

    it "should be able to bypass authentication by setting its pubkey to N (37c)" do
      client = CryptoToolchain::SRP::Client.new(socket: s1, pubkey: CryptoToolchain::NIST_P**2)
      start_threading(client, server)
      client.send_hello
      sleep(0.25)

      expect(server.key).to eq Digest::SHA256.hexdigest("0")
      expect(client.authenticated?).to be true
    end
  end
end
