module CryptoToolchain
  module Tools
    class AesCtrRecoverer

      attr_reader :ciphertext, :editor

      def initialize(editor)
        @editor = editor
        @ciphertext = editor.ciphertext
      end

      def execute
        (0...(ciphertext.length)).each_with_object("") do |i, memo|
          memo << get_character(i)
        end
      end

      def get_character(i)
        (0..255).each do |byte|
          chr = byte.chr
          if editor.edit(offset: i, with: chr) == ciphertext
            return chr
          end
        end
        raise RuntimeError, "Could not recover character"
      end

    end
  end
end
