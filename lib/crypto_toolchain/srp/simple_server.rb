module CryptoToolchain
  module SRP
    class SimpleServer < Server
      include SRP::Framework

      def initialize(n: CryptoToolchain::NIST_P, g: CryptoToolchain::NIST_G,
                    k: 3, email: "charles@goodog.com", password: "i<3porkchops",
                    privkey: nil, pubkey: nil, u: (rand(1..0x0000ffff)), malicious: false,
                    salt: rand(1..0xffffffff), socket: )
        @n        = n
        @g        = g
        @k        = k
        @email    = email,
        @password = password
        @socket   = socket
        @privkey  = privkey || rand(1..0xffffffff) % n
        @pubkey    = pubkey || g.modpow(@privkey, n)
        @u         = u
        @salt      = salt
        xH         = Digest::SHA256.hexdigest("#{salt}#{password}")
        x          = xH.to_i(16)
        @v         = g.modpow(x, n)
        @malicious = malicious
      end

      attr_reader :salt, :u, :malicious, :recovered_password
      alias_method :malicious?, :malicious

      def hello_received(email, _client_pubkey)
        @client_pubkey = _client_pubkey.to_i
        u = rand((1..0xffff))
        write_message("hello", salt, pubkey, u)
        #  S = (A * v**u) ** b % N
        secret = (client_pubkey * v.modpow(u, n)).modpow(privkey, n)
        puts "SimpleServer generated secret #{secret}" if DEBUG
        @key = Digest::SHA256.hexdigest(secret.to_s)
      end

      def wordlist
        return @wordlist if defined? @wordlist
        _words = File.readlines("/usr/share/dict/words").
          shuffle[0...100].
          map(&:strip)
        _words << "i<3porkchops"
        @wordlist = _words.shuffle
      end

      def crack(hmac)
        wordlist.each_with_index do |word, i|
          _x = Digest::SHA256.hexdigest("#{salt}#{word}").to_i(16)
          _v = g.modpow(_x, n)
          _secret = (client_pubkey * _v.modpow(u, n)).modpow(privkey, n)
          _key = Digest::SHA256.hexdigest(_secret.to_s)
          word_hmac = OpenSSL::HMAC.hexdigest("SHA256", _key, salt.to_s)
          return word if word_hmac == hmac
        end
        nil
      end

      def verify_received(hmac)
        if malicious?
          @recovered_password = crack(hmac)
          puts "Recovered #{@recovered_password}" if DEBUG
        end
        super(hmac)
      end
    end
  end
end
