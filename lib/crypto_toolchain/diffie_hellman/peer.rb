module CryptoToolchain
  module DiffieHellman
    class Peer
      def initialize(debug: false, name: SecureRandom.uuid, p: NIST_P, g: NIST_G)
        @addresses = []
        @channel = Queue.new
        @name = name
        @debug = debug
        @p = p
        @g = g
      end

      def process!
        loop do
          while(channel.empty?)
            sleep 0.010
          end
          msg = channel.pop
          if msg.respond_to?(:peer)
            puts "#{name} got #{msg.class.to_s.split(':').last} from #{msg.peer.name}" if debug
          end
          case msg
          when Messages::Die
            puts "Dying" if debug
            break
          when Messages::PeerAddress
            @addresses << msg
            if msg.initial?
              send_msg msg.peer, my_address_message
            end
            puts "#{name} added #{msg.peer.name}" if debug
          # when Messages::PeerAddress
          #   @addresses << msg
          #   puts "#{name} added #{msg.peer.name}" if debug
          when Messages::KeyExchange #Params
            info = info_for(msg.peer)
            info.pubkey = msg.pubkey
            info.shared_secret = shared_secret_for(msg.pubkey)
            puts "#{name} generated secret #{info.shared_secret}" if debug
            if msg.initial?
              send_msg msg.peer, my_pubkey_message
            end
          else
            raise RuntimeError.new("Don't know how to process #{msg.class}")
          end
        end
      end
      alias_method :process, :process!

      def shared_secret_for(peer_pubkey)
         peer_pubkey.modexp(privkey, p)
      end

      def send_msg(peer, message)
        puts "#{name} sends #{message.class.to_s.split(':').last} to #{peer.name}" if debug
        peer.channel.enq(message)
      end

      def info_for(peer)
        ret = addresses.select {|addr| addr.peer.name == peer.name }.first
        if ret.nil?
          raise StandardError.new("Peer #{peer.name} is unknown")
        end
        ret
      end

      def pubkey
        @pubkey ||= g.modexp(privkey, p)
      end

      def privkey
        @privkey ||= rand(1..0xffffffff) % p
      end

      def my_pubkey_message
        Messages::KeyExchange.new(peer: self, pubkey: pubkey, initial: false)
      end

      def my_address_message
        Messages::PeerAddress.new(peer: self, channel: self.channel, initial: false)
      end

      attr_reader :addresses, :channel, :name, :debug, :p, :g
      alias_method :debug?, :debug
    end
  end
end
