Thread.abort_on_exception = true
module CryptoToolchain
  module DiffieHellman
    class MITMGParameter < MITM
      def key_exchange_response(msg)
        info = info_for(msg.peer)
        info.update(pubkey: msg.pubkey)
        info.set_shared_secret(privkey)
        if debug
          puts "#{msg}"
          puts "#{name} will use p = #{p}"
          puts "#{name} will use g = #{g}"
          puts "#{name} thinks #{msg.peer.name} has pubkey #{msg.pubkey}"
          puts "#{name} generated secret #{info.shared_secret} for #{msg.peer.name}"
        end
      end

      attr_reader :new_g

    end
  end
end
