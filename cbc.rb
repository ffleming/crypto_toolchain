# encoding: ASCII-8BIT
require_relative("./string_utils")

AES_BLOCK_SIZE=16
DEBUG = false
QUIET = true

def run_tests
  unless ciphertext.valid_padding?
    raise StandardError, "Test failed for valid cbc"
  end
  str = "gibberish"
  if str.valid_padding?
    raise StandardError, "Test failed for invalid cbc"
  end
  puts "Tests passed"
end

def ciphertext
  @ciphertext ||= Base64.strict_decode64('SNXIDUFQW0Ul6GXI4NyU/LMHl+vRlVIYp4pvFstfpP1n1C9Xhbl/bNip6mK5l7TMPS+vw247XTYK3LKIGT4AZVh6zUB97fN3fOamkLvzpmA=')
end

def already_known?(guess, byte_index, block_index)
  if block_index == 4
    return true if byte_index == 15 && guess == 0x74
    return true if byte_index == 14 && guess == 0x12
    return true if byte_index == 13 && guess == 0x2d
    return true if byte_index == 12 && guess == 0x0d
    return true if byte_index == 11 && guess == 0x9d
    return true if byte_index == 10 && guess == 0xa4
    return true if byte_index == 9 && guess == 0xcb
    return true if byte_index == 8 && guess == 0x12
    return true if byte_index == 7 && guess == 0x2f
    return true if byte_index == 6 && guess == 0x47
    return true if byte_index == 5 && guess == 0x20
    return true if byte_index == 4 && guess == 0x72
    return true if byte_index == 3 && guess == 0xde
    return true if byte_index == 2 && guess == 0xb1
    return true if byte_index == 1 && guess == 0x30
    return true if byte_index == 0 && guess == 0x3d
  end
  if block_index == 3
    return true if byte_index == 15 && guess == 0xbb
    return true if byte_index == 14 && guess == 0xdb
    return true if byte_index == 13 && guess == 0xac
    return true if byte_index == 12 && guess == 0xd8
    return true if byte_index == 11 && guess == 0x53
    return true if byte_index == 10 && guess == 0xa8
    return true if byte_index == 9 && guess == 0xf4
    return true if byte_index == 8 && guess == 0xe0
    return true if byte_index == 7 && guess == 0x2c
    return true if byte_index == 6 && guess == 0x04
    return true if byte_index == 5 && guess == 0xe4
    return true if byte_index == 4 && guess == 0xcb
    return true if byte_index == 3 && guess == 0x68
    return true if byte_index == 2 && guess == 0x53
    return true if byte_index == 1 && guess == 0x8a
    return true if byte_index == 0 && guess == 0x31
  end
  if block_index == 2
    return true if byte_index == 15 && guess == 0xac
    return true if byte_index == 14 && guess == 0xd1
    return true if byte_index == 13 && guess == 0x39
    return true if byte_index == 12 && guess == 0xb5
    return true if byte_index == 11 && guess == 0x65
    return true if byte_index == 10 && guess == 0x2d
    return true if byte_index == 9 && guess == 0xf7
    return true if byte_index == 8 && guess == 0xec
    return true if byte_index == 7 && guess == 0x7b
    return true if byte_index == 6 && guess == 0x1a
    return true if byte_index == 5 && guess == 0xd6
    return true if byte_index == 4 && guess == 0x9f
    return true if byte_index == 3 && guess == 0xa7
    return true if byte_index == 2 && guess == 0xd6
    return true if byte_index == 1 && guess == 0x4b
    return true if byte_index == 0 && guess == 0xf6
  end
  if block_index == 1
    return true if byte_index == 15 && guess == 0xdd
    return true if byte_index == 14 && guess == 0xe5
    return true if byte_index == 13 && guess == 0xb6
    return true if byte_index == 12 && guess == 0xc4
    return true if byte_index == 11 && guess == 0xa9
    return true if byte_index == 10 && guess == 0x11
    return true if byte_index == 9 && guess == 0x80
    return true if byte_index == 8 && guess == 0x5a
    return true if byte_index == 7 && guess == 0x3f
    return true if byte_index == 6 && guess == 0x22
    return true if byte_index == 5 && guess == 0x3a
    return true if byte_index == 4 && guess == 0x3d
    return true if byte_index == 3 && guess == 0x20
    return true if byte_index == 2 && guess == 0xa3
    return true if byte_index == 1 && guess == 0xb2
    return true if byte_index == 0 && guess == 0x0c
  end
  false
end

def random_bytes(len)
  len.times.with_object("") do |i, ret|
    ret << rand(256).chr
  end
end

def decrypt_string
  blocks = ciphertext.in_blocks(AES_BLOCK_SIZE).reverse
  blocks.map.with_index do |block, i|
    next unless i < blocks.size-1 # We can't decrypt the first (last, when reversed) block
    target = block
    preceding = blocks[i + 1]
    intermediate = decrypt_block(preceding: preceding, target: target, block_index: (blocks.size-1)-i)
    intermediate ^ preceding
  end.reverse
end

def decrypt_block(preceding: , target: , block_index: )
  raise ArgumentError.new("Blocks must be the same size") unless preceding.bytesize == target.bytesize
  intermediate = "\x00" * target.size
  (0...target.size).to_a.reverse_each do |i|
    intermediate = decrypt_byte(byte_index: i, target: target, preceding: preceding, intermediate: intermediate, block_index: block_index)
  end
  intermediate
end

def status_line_from(guess, intermediate, solved)
  "#{guess.to_hex.ljust(32)} | #{intermediate.to_hex.ljust(32)} | #{solved.rjust(16)}"
end

def header_line
  "#{'Guess'.ljust(32)} | #{'Intermediate (hex)'.ljust(32)} | #{'Solved'.rjust(16)}"
end

def decrypt_byte(byte_index: , preceding: , target: , intermediate: "\x00" * 16, block_index:)
  unless(preceding.bytes.length == AES_BLOCK_SIZE && target.bytes.length == AES_BLOCK_SIZE)
    raise ArgumentError.new("Length should be #{AES_BLOCK_SIZE}")
  end
  padding = ((16 - byte_index).chr * (16 - byte_index)).rjust(16, 0x00.chr)
  candidate = padding ^ intermediate ^ preceding
  puts "Expected padding: #{padding.to_hex}" if DEBUG
  puts "preceding: #{preceding.to_hex}" if DEBUG
  (0..255).each do |guess|
    next unless already_known?(guess, byte_index, block_index)
    if preceding.bytes[byte_index] == guess && byte_index == AES_BLOCK_SIZE-1
      puts "\nnext" if DEBUG
      next
    end
    candidate = padding ^ intermediate
    candidate[byte_index] = guess.chr
    attempt = candidate + target
    solved = (intermediate ^ preceding)[(byte_index)+1..-1]
    print "\r#{status_line_from(candidate, intermediate, solved)}" unless QUIET
    if attempt.valid_padding?
      next_intermediate = intermediate.clone
      puts "\nvalid padding for 0x#{guess.to_s(16)}" if DEBUG
      next_intermediate[byte_index] = (guess ^ padding.bytes.last).chr
      puts "Solved #{(next_intermediate.bytes[byte_index] ^ preceding.bytes[byte_index])}" if DEBUG
      puts "Next: #{next_intermediate.to_hex}" if DEBUG
      return next_intermediate
    end
  end
  raise RuntimeError.new("Didn't find valid padding")
end

blocks = ciphertext.in_blocks(AES_BLOCK_SIZE)

case ARGV[0]
when 'console'
  binding.pry
  exit
when 'test'
  run_tests
  exit
end

puts header_line unless QUIET
puts decrypt_string

