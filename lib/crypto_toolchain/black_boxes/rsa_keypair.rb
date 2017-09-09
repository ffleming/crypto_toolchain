# encoding: ASCII-8BIT
module CryptoToolchain
  module BlackBoxes
    class RSAKeypair
      PrivateKey = Struct.new(:d, :n)
      PublicKey = Struct.new(:e, :n)

      def initialize(bits: 1024)
        @bits = bits
        @p = OpenSSL::BN::generate_prime(bits/2).to_i
        @q = OpenSSL::BN::generate_prime(bits/2).to_i
        @n = @p * @q
        et = (@p-1) * (@q-1)
        @e = 3
        @d = @e.invmod(et)
      end

      attr_reader :e, :bits

      def encrypt(m, to: )
        raise ArgumentError.new("Message should be a string") unless m.is_a?(String)
        m.
          to_number.
          modpow(to.e, to.n).
          to_bin_string
      end

      def decrypt(m)
        raise ArgumentError.new("Message should be a string") unless m.is_a?(String)
        m.
          to_number.
          modpow(private_key.d, private_key.n).
          to_bin_string
      end

      def sign(plaintext)
        blocksize = bits / 8
        digest = CryptoToolchain::Utilities::SHA1.digest(plaintext)
        asn = asn1(:sha1)
        # the 4 is the mandatory 0x00 0x01 0xff 0x00
        pad_num = blocksize - ( digest.bytesize + asn.bytesize + 4)
        block = "\x00\x01\xff" + (0xff.chr * pad_num) + "\x00" + asn + digest
        decrypt(block)
      end

      def verify(message, signature: , lazy: true)
        raise("I can't not be lazy") unless lazy
        enc = encrypt(signature, to: pubkey)
        asn = ASN1.fetch(:sha1)
        regex = /(?<padding>\x01\xff+\x00)(?<asn>.{#{asn.bytesize}})(?<hash>.{20})/m
        begin
          _padding, potential_asn, hash = enc.match(regex).captures
        rescue
          return false
        end
        potential_asn == asn && hash == CryptoToolchain::Utilities::SHA1.digest(message)
      end

      def public_key
        @public_key ||= PublicKey.new(@e, @n)
      end
      alias_method :pubkey, :public_key

      def private_key
        @private_key ||= PrivateKey.new(@d, @n)
      end
      alias_method :privkey, :private_key

      # Values from
      # https://stackoverflow.com/questions/3713774/c-sharp-how-to-calculate-asn-1-der-encoding-of-a-particular-hash-algorithm
      def asn1(hash_type)
        raise ArgumentError.new("Only sha1 is supported") unless hash_type == :sha1
        {
          md5:    "0 0\f\x06\b*\x86H\x86\xF7\r\x02\x05\x05\x00\x04\x10",
          sha1:   "0!0\t\x06\x05+\x0E\x03\x02\x1A\x05\x00\x04\x14",
          sha256: "010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 ",
          sha384: "0A0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\x040",
          sha512: "0Q0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\x04@"
        }.fetch(hash_type)
      end
    end
  end
end
