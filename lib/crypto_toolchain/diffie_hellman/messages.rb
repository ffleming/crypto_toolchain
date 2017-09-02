module CryptoToolchain
  module DiffieHellman
    module Messages
      class Die ; end

      class PeerAddress
        def initialize(peer: , channel: , initial: false)
          @peer = peer
          @channel = channel
          @initial = initial
        end
        attr_reader :peer, :channel, :initial
        alias_method :initial?, :initial
        attr_accessor :pubkey, :shared_secret
      end

      class KeyExchange
        def initialize(peer: , pubkey: , p: nil, g: nil, initial: false)
          if initial && (p.nil? || g.nil?)
            raise ArgumentError.new("Initial message must provide p and g")
          end
          @p = p
          @g = g
          @pubkey = pubkey
          @peer = peer
          @initial = initial
        end
        attr_reader :p, :g, :peer, :pubkey, :initial
        alias_method :initial?, :initial

        def to_s
          "PEER: #{peer.name} P: #{p} G: #{g} PUBKEY: #{pubkey % 1000}"
        end
      end

      class Datum
        def initialize(peer: , contents: , initial: false)
          @peer = peer
          @contents = contents
          @initial = initial
        end

        def decrypt(key: )
          iv = contents[0..15]
          contents[16..-1].decrypt_cbc(key: key, iv: iv)
        end

        attr_reader :peer, :contents, :initial
        alias_method :initial?, :initial
      end
    end
  end
end
