require 'spec_helper'
RSpec.describe CryptoToolchain::DiffieHellman::MITMGParameter do
  let(:msg) { CryptoToolchain::DiffieHellman::Messages }
  let(:a) { CryptoToolchain::DiffieHellman::Peer.new(name: "A", p: nil, g: nil) }
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

  context "fixing g to 1" do
    let(:mitm) { CryptoToolchain::DiffieHellman::MITMGParameter.new(name: "MITM",
                                                                    peer_a: a,
                                                                    peer_b: b,
                                                                    p: p,
                                                                    g: 1) }


    it "should set the shared secret to 1 (35a)" do
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
  end

  context "fixing g to p" do
    let(:mitm) { CryptoToolchain::DiffieHellman::MITMGParameter.new(name: "MITM",
                                                                    peer_a: a,
                                                                    peer_b: b,
                                                                    p: p,
                                                                    g: p) }

    it "should set the shared secret to 0 (35b)" do
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
  end

  context "fixing g to p-1" do
    let(:mitm) { CryptoToolchain::DiffieHellman::MITMGParameter.new(name: "MITM",
                                                                    peer_a: a,
                                                                    peer_b: b,
                                                                    p: p,
                                                                    g: p-1) }

    it "should set the shared secret to 1 (35c)" do
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
end
