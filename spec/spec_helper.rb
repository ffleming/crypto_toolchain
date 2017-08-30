$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "crypto_toolchain"
RSpec.configure do |config|
  config.profile_examples = 3
end
