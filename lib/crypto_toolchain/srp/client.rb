module CryptoToolchain
  module SRP
    class Client
      include SRP::Framework

      attr_reader :server_pubkey, :authenticated
      alias_method :authenticated?, :authenticated

      def initialize(**kargs)
        provided_pubkey = kargs.delete(:pubkey)
        super(**kargs)
        @pubkey = provided_pubkey || g.modpow(privkey, n)
      end

      def send_hello
        write_message("hello", email, pubkey)
      end

      def send_verify
        hmac = OpenSSL::HMAC.hexdigest("SHA256", key.to_s, salt.to_s)
        write_message("verify", hmac)
      end

      def hello_received(_salt, _server_pubkey)
        @salt = _salt.to_i
        @server_pubkey = _server_pubkey.to_i
        secret = calculate_secret
        puts "Client generated secret #{secret}" if DEBUG
        @key = Digest::SHA256.hexdigest(secret.to_s)
        send_verify
      end

      def authentication_success_received
        @authenticated = true
        write_message("shutdown")
        raise ShutdownSignal
      end

      def calculate_secret
        return 0 if [0, n, n**2, n**3].include?(pubkey)

        xH = Digest::SHA256.hexdigest("#{salt}#{password}")
        x = xH.to_i(16)
        uH = Digest::SHA256.hexdigest("#{pubkey}#{server_pubkey}")
        u = uH.to_i(16)
        # S = (B - k * g**x)**(a + u * x) % N
        (server_pubkey - k * g.modpow(x, n)).modpow(privkey + u * x, n)
      end
    end
  end
end
