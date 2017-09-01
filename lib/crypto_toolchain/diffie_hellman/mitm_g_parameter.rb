Thread.abort_on_exception = true
module CryptoToolchain
  module DiffieHellman
    class MITMGParameter < MITM
      G_OPTIONS = %i(one p p_minus_one)
      def initialize(kargs)
        @new_g = kargs.delete(:new_g)
        unless G_OPTIONS.include?(@new_g)
          raise ArgumentError.new("new_g must be in [#{G_OPTIONS.join(', ')}]")
        end
        kargs[:debug] = true
        super(**kargs)
      end

      def injected_g
        {
          one:         1,
          p:           p,
          p_minus_one: p - 1
        }.fetch(new_g)
      end

      def do_key_exchange
        msg = Messages::KeyExchange.new(peer: self, pubkey: injected_pubkey, p: p, g: injected_g, initial: true)
        [peer_a, peer_b].each do |peer|
          send_msg(peer, msg)
          info_for(peer).update(p: p, g: injected_g)
        end
      end

      def injected_pubkey
        injected_g.modexp(privkey, p)
      end

      def key_exchange_response(msg)
        info = info_for(msg.peer)
        info.update(p: msg.p, g: msg.g, pubkey: msg.pubkey)
        info.set_shared_secret(privkey)
        puts "#{name} generated secret #{info.shared_secret} for #{msg.peer.name}" if debug
      end

      attr_reader :new_g

    end
  end
end
