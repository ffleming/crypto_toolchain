# encoding: ASCII-8BIT
module CryptoToolchain
  module Tools
    class SHA1LengthExtensionAttack
      def initialize(message: , add: , mac: , key_length: )
        @message = message
        @mac = mac
        @add = add
        @key_length = key_length
      end

      # @return Array [msg, digest] Message that can be validated
      def execute
        registers = CryptoToolchain::Utilities::SHA1.registers_for(mac)
        dummy_key = "A" * key_length
        padding = CryptoToolchain::Utilities::SHA1.padding(dummy_key + message)
        [
          message + padding + add,
          CryptoToolchain::Utilities::SHA1.hexdigest(add,
                                                     registers: registers,
                                                     append_length: (padding + message + dummy_key).length
                                                    )
        ]
      end

      attr_reader :message, :mac, :add, :key_length

    end
  end
end

