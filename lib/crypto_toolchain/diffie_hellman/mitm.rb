module CryptoToolchain
  module DiffieHellman
    class MITM < Peer
      def initialize(debug: false, name: "MITM", p: NIST_P, g: NIST_G, peer_a: , peer_b: )
        @peer_a = peer_a
        @peer_b = peer_b
        super(debug: debug, name: name, p: p, g: g)
        [peer_a, peer_b].each do |peer|
          puts "Adding #{peer.name} to #{name} at startup" if debug
          add_address(peer)
        end
      end

      def peer_address_response(msg)
        send_msg other_peer(msg.peer), my_address_message(initial: msg.initial)
      end

      def key_exchange_response(msg)
        info = info_for(msg.peer)
        other = other_peer(msg.peer)
        if msg.initial?
          @p = msg.p
          @g = msg.g
          send_msg(other, injected_initial_key_exchange)
        else
          send_msg(other, injected_b_to_a_pubkey)
        end
        info.update(p: p, g: g, pubkey: p)
        info.set_shared_secret(privkey)
        puts "#{name} generated secret #{info.shared_secret} for #{msg.peer.name}" if debug
      end

      def datum_response(msg)
        data = msg.decrypt(key: info_for(msg.peer).session_key)
        puts "#{name} got message containing #{data} from #{msg.peer.name}" if debug
        other = other_peer(msg.peer)
        encrypted = encrypted_message_for(other, message: data, initial: msg.initial)
        send_msg(other, encrypted)
        @received_messages << ReceivedMessage.new(from: msg.peer.name, contents: data)
      end

      def other_peer(peer)
        peer == peer_a ? peer_b : peer_a
      end

      def injected_initial_key_exchange
        Messages::KeyExchange.new(peer: self, pubkey: p, p: p, g: g, initial: true)
      end

      def injected_b_to_a_pubkey
        Messages::KeyExchange.new(peer: self, pubkey: p, initial: false)
      end

     attr_reader :peer_a, :peer_b
    end
  end
end
