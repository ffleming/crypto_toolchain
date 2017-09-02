module CryptoToolchain
  module SRP
    class SimpleClient < Client
      include SRP::Framework

      attr_reader :u

      def initialize(**kargs)
        provided_pubkey = kargs.delete(:pubkey)
        super(**kargs)
        @pubkey = provided_pubkey || g.modpow(privkey, n)
      end

      def hello_received(_salt, _server_pubkey, _u)
        @salt = _salt.to_i
        @server_pubkey = _server_pubkey.to_i
        @u = _u.to_i
        secret = calculate_secret
        puts "SimpleClient generated secret #{secret}" if DEBUG
        @key = Digest::SHA256.hexdigest(secret.to_s)
        send_verify
      end

      def calculate_secret
        xH = Digest::SHA256.hexdigest("#{salt}#{password}")
        x = xH.to_i(16)
        # S = B**(a + ux) % n
        server_pubkey.modpow(privkey + (u * x), n)
      end
    end
  end
end
