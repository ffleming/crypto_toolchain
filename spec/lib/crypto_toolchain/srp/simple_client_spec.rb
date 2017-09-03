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

    client.socket.puts("shutdown")
    expect(server.key).to eq client.key
    expect(client.authenticated?).to be true
  end

  it "should be able to crack a client's password (38b)" do
    client = CryptoToolchain::SRP::SimpleClient.new(socket: s1)
    server = CryptoToolchain::SRP::SimpleServer.new(socket: s2, malicious: true, salt: 1, privkey: 1)
    start_threading(client, server)
    client.send_hello
    sleep(0.75)

    sockets.each {|s| s.puts("shutdown") }

    while(server.recovered_password.nil?)
      sleep(0.1)
    end

    expect(server.recovered_password).to eq client.password
  end
end
