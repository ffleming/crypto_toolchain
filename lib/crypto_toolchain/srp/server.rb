module CryptoToolchain
  module SRP
    class Server
      include SRP::Framework

      attr_reader :v, :client_pubkey

      def initialize(**kargs)
        super(**kargs)
        @salt = rand(1..0xffffffff)
        xH = Digest::SHA256.hexdigest("#{salt}#{password}")
        x = xH.to_i(16)
        @v = g.modpow(x, n)
        @pubkey = k*v + g.modpow(privkey, n)
      end

      def hello_received(email, _client_pubkey)
        @client_pubkey = _client_pubkey.to_i
        write_message("hello", salt, pubkey)
        uH = Digest::SHA256.hexdigest("#{client_pubkey}#{pubkey}")
        u = uH.to_i(16)
        #  S = (A * v**u) ** b % N
        secret = (client_pubkey * v.modpow(u, n)).modpow(privkey, n)
        puts "Server generated secret #{secret}" if DEBUG
        @key = Digest::SHA256.hexdigest(secret.to_s)
      end

      def verify_received(hmac)
        valid_hmac = OpenSSL::HMAC.hexdigest("SHA256", key.to_s, salt.to_s)
        if hmac == valid_hmac
          write_message("authentication_success")
        else
          write_message("error", "invalid_hmac")
        end
      end
    end
  end
end
