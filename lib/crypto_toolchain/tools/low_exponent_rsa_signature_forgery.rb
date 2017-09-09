# encoding: ASCII-8BIT
module CryptoToolchain
  module Tools
    class LowExponentRSASignatureForgery
      def initialize(message: , keypair: )
        @keypair = keypair
        @message = message
      end
      attr_reader :keypair, :message

      def execute
        digest = CryptoToolchain::Utilities::SHA1.digest(message)
        asn = ASN1.fetch(:sha1)
        max = (keypair.bits / 8) - (asn.bytesize + digest.bytesize + 3)
        (1..max).reverse_each do |padlen|
          forged = "\x01\xff\x00#{asn}#{digest}#{0.chr * padlen}".
            to_number.
            root(3, round: :up).
            to_bin_string
          found = keypair.verify(message, signature: forged)
          return forged if found
        end
        raise RuntimeError.new("Couldn't forge a signature")
      end
    end
  end
end
