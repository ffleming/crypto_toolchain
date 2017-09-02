require 'spec_helper'

RSpec.describe CryptoToolchain::SRP::Client do
  let(:sockets) { UNIXSocket.pair }
  let(:s1) { sockets.first }
  let(:s2) { sockets.last }
  let(:server) { CryptoToolchain::SRP::Server.new(socket: s2) }

  def start_threading(*instances)
    @threads = instances.map do |p|
      Thread.new { p.go! }
    end
  end

  after(:each) { @threads.each(&:join) }

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
