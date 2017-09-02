module CryptoToolchain
  module DiffieHellman
    class Peer
      def initialize(debug: false, name: SecureRandom.uuid, p: NIST_P, g: NIST_G)
        @addresses = {}
        @channel = Queue.new
        @name = name
        @debug = debug
        @p = p
        @g = g
        @received_messages = []
      end

      def process!
        when_ready do
          msg = channel.pop
          message_type = msg.class.to_s.split(':').last
          if msg.respond_to?(:peer)
            puts "#{name} got #{message_type} from #{msg.peer.name}" if debug
          end
          method = "#{message_type}_response".snakecase
          unless self.respond_to?(method)
            raise ArgumentError.new("Don't know how to process method :#{method}")
          end
          begin
            send(method, msg)
          rescue ReceivedDie
            break
          end
        end
      end
      alias_method :process, :process!

      def die_response(msg)
        raise ReceivedDie
      end

      def add_address(peer)
        @addresses[peer.name] ||= PeerInfo.new(peer: peer, channel: peer.channel )
      end

      def peer_address_response(msg)
        add_address(msg.peer)
        if msg.initial?
          send_msg msg.peer, my_address_message
        end
        puts "#{name} added #{msg.peer.name}" if debug
      end

      def key_exchange_response(msg)
        info = info_for(msg.peer)
        if msg.initial?
          @p = msg.p
          @g = msg.g
        end
        info.update(p: p, g: g, pubkey: msg.pubkey)
        info.set_shared_secret(privkey)
        if debug
          puts "#{name} will use p = #{p}"
          puts "#{name} will use g = #{g}"
          puts "#{name} thinks #{msg.peer.name} has pubkey #{msg.pubkey}"
          puts "#{name} generated secret #{info.shared_secret} for #{msg.peer.name}"
        end
        my_pubkey_msg = Messages::KeyExchange.new(peer: self, pubkey: pubkey, initial: false)
        send_msg msg.peer, my_pubkey_msg if msg.initial?
      end

      def datum_response(msg)
        data = msg.decrypt(key: info_for(msg.peer).session_key)
        puts "#{name} got message containing #{data} from #{msg.peer.name}" if debug
        if msg.initial?
          encrypted = encrypted_message_for(msg.peer, message: data, initial: false)
          send_msg(msg.peer, encrypted)
        end
        @received_messages << ReceivedMessage.new(from: msg.peer.name, contents: data)
      end

      def when_ready
        loop do
          while(channel.empty?)
            sleep 0.001
          end
          yield
        end
      end

      def send_msg(peer, message)
        puts "#{name} sends #{message.class.to_s.split(':').last} to #{peer.name}" if debug
        peer.channel.enq(message)
      end

      def info_for(peer)
        addresses[peer.name]
      end

      def pubkey
        raise RuntimeError.new("Can't generate public key until p has been set") if p.nil?
        raise RuntimeError.new("Can't generate public key until g has been set") if g.nil?
        @pubkey ||= g.modexp(privkey, p)
      end

      def privkey
        raise RuntimeError.new("Can't generate private key until p has been set") if p.nil?
        @privkey ||= rand(1..0xffffffff) % p
      end

      def my_address_message(initial: false)
        Messages::PeerAddress.new(peer: self, channel: self.channel, initial: initial)
      end

      def encrypted_message_for(peer, message: , initial: false)
        key = info_for(peer).session_key
        iv = Random.new.bytes(16)
        encrypted = (iv + message.encrypt_cbc(key: key, iv: iv))
        Messages::Datum.new(peer: self, contents: encrypted, initial: initial)
      end

      attr_reader :addresses, :channel, :name, :debug, :p, :g, :received_messages
      alias_method :debug?, :debug
    end
  end
end
