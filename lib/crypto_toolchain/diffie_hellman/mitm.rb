Thread.abort_on_exception = true
module CryptoToolchain
  module DiffieHellman
    class MITM < Peer
      def initialize(debug: false, name: "MITM", p: NIST_P, g: NIST_G, peer_a: , peer_b: , pubkey: nil)
        @peer_a = peer_a
        @peer_b = peer_b
        @pubkey = pubkey
        super(debug: debug, name: name, p: p, g: g)
        [peer_a, peer_b].each do |peer|
          puts "Adding #{peer.name} to #{name} at startup" if debug
          add_address(peer)
        end
      end

      def peer_address_response(msg)
        send_msg other_peer(msg.peer), my_address_message(initial: msg.initial)
      end

      def do_key_exchange
        msg = Messages::KeyExchange.new(peer: self, pubkey: pubkey, p: p, g: g, initial: true)
        [peer_a, peer_b].each do |peer|
          info_for(peer).update(p: p, g: g)
          send_msg(peer, msg)
        end
      end

      def key_exchange_response(msg)
        info = info_for(msg.peer)
        info.update(pubkey: msg.pubkey)
        # Ignore what their actual pubkey is - we tricked them into settling upon a secret of 0
        info.set_shared_secret(privkey)
        info.instance_variable_set("@shared_secret", 0)
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

     attr_reader :peer_a, :peer_b
    end
  end
end
