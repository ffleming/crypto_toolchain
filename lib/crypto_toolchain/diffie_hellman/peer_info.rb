module CryptoToolchain
  module DiffieHellman
    class PeerInfo
      def initialize(peer: , channel: , pubkey: nil, p: nil, g: nil)
        @peer = peer
        @channel = channel
        @pubkey = pubkey
        @p = p
        @g = g
      end
      attr_reader :peer, :channel, :shared_secret
      attr_accessor :p, :g, :pubkey

      def to_h
        {
          name:   peer.name,
          p:      p,
          g:      g,
          pubkey: pubkey,
          secret: shared_secret
        }
      end

      def set_shared_secret(privkey)
        @shared_secret = pubkey.modexp(privkey, p)
      end

      def session_key
        if shared_secret.nil?
          raise ArgumentError.new("Session key requires a shared secret")
        end
        @session_key ||= CryptoToolchain::Utilities::SHA1.bindigest(shared_secret.to_s)[0..15]
      end

      def update(hsh)
        hsh.each do |k, v|
          self.send("#{k}=", v)
        end
      end
    end
  end
end
