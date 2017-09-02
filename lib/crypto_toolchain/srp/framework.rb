module CryptoToolchain
  module SRP
    module Framework

      attr_reader :n, :g, :k, :email, :password, :socket, :privkey, :pubkey, :salt, :key

      def initialize(n: CryptoToolchain::NIST_P, g: CryptoToolchain::NIST_G,
                    k: 3, email: "charles@goodog.com", password: "i<3porkchops",
                    socket: )
        @n        = n
        @g        = g
        @k        = k
        @email    = email
        @password = password
        @socket   = socket
        @privkey  = rand(1..0xffffffff) % n
      end

      EVENT_WHITELIST = %w( hello verify shutdown error authentication_success ).freeze
      def go!
        event_loop do |event_string|
          event_type, *data = event_string.split(DELIMITER)
          puts "Received #{event_type} #{data}" if DEBUG
          if !EVENT_WHITELIST.include?(event_type)
            socket.puts("error|event #{event_type} unknown") and next
          end
          send("#{event_type}_received", *data)
        end
      end

      def event_loop
        begin
          loop do
            yield socket.readline.strip
          end
        rescue ShutdownSignal
          # Nothing
        end
      end

      def shutdown_received(*args)
        raise ShutdownSignal.new
      end

      def write_message(*args)
        socket.puts args.join(DELIMITER)
      end

      def error_received(*args)
        raise StandardError.new(args.join(" "))
      end
    end

  end
end
