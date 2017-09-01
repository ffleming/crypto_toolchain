# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'crypto_toolchain/version'

Gem::Specification.new do |spec|
  spec.name          = "crypto_toolchain"
  spec.version       = CryptoToolchain::VERSION
  spec.authors       = ["Forrest Fleming"]
  spec.email         = ["ffleming@gmail.com"]

  spec.summary       = "Crypto toolchain for CTFs and so on"
  spec.description   = "A toolchain for manipulating data in a variety of cryptographic " <<
                       "and quasi-cryptographic ways."
  spec.homepage      = "https://github.com/ffleming/crypto_toolchain"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "pry-byebug", "3.4"
  spec.add_runtime_dependency "openssl", "~> 2.0"
  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "guard-rspec"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "simplecov", "~> 0.15"
end
