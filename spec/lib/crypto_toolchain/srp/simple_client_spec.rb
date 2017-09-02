require 'spec_helper'

RSpec.describe CryptoToolchain::SRP::SimpleClient do
  let(:sockets) { UNIXSocket.pair }
  let(:s1) { sockets.first }
  let(:s2) { sockets.last }
  let(:server) { CryptoToolchain::SRP::SimpleServer.new(socket: s2) }

  def start_threading(*instances)
    @threads = instances.map do |p|
      Thread.new { p.go! }
    end
  end

  after(:each) { @threads.each(&:join) }

  it "should authenticate using a simplified SRP protocol (38a)" do
    client = CryptoToolchain::SRP::SimpleClient.new(socket: s1)
    start_threading(client, server)
    client.send_hello
    sleep(0.25)

    expect(server.key).to eq client.key
    expect(client.authenticated?).to be true
  end
end
