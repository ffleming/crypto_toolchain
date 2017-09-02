module CryptoToolchain
  module SRP
    class SimpleServer < Server
      include SRP::Framework

      def initialize(**kargs)
        super(**kargs)
        @pubkey = g.modpow(privkey, n)
      end

      def hello_received(email, _client_pubkey)
        @client_pubkey = _client_pubkey.to_i
        u = rand((1..0xffff))
        write_message("hello", salt, pubkey, u)
        #  S = (A * v**u) ** b % N
        secret = (client_pubkey * v.modpow(u, n)).modpow(privkey, n)
        puts "SimpleServer generated secret #{secret}" if DEBUG
        @key = Digest::SHA256.hexdigest(secret.to_s)
      end
    end
  end
end
