require 'spec_helper'

RSpec.describe CryptoToolchain::SRP::Framework do
  it "should negotiate a shared secret and authenticate" do
    s1, s2 = UNIXSocket.pair
    client = CryptoToolchain::SRP::Client.new(socket: s1)
    server = CryptoToolchain::SRP::Server.new(socket: s2)
    threads = [client,server].map do |p|
      Thread.new do
        p.go!
      end
    end
    client.send_hello
    sleep(0.25)

    expect(client.key).to eq server.key
    expect(client.authenticated?).to be true

    threads.each(&:join)
  end
end
