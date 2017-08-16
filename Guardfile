guard :rspec, cmd: "bundle exec rspec" do
  require "guard/rspec/dsl"
  dsl = Guard::RSpec::Dsl.new(self)

  # RSpec files
  rspec = dsl.rspec
  watch(rspec.spec_helper) { rspec.spec_dir }
  watch(rspec.spec_support) { rspec.spec_dir }
  watch(rspec.spec_files)

  watch(%r{^lib/(.+)\.rb$})     { |m| ret =  "spec/lib/#{m[1]}_spec.rb" ; puts ret ; puts '!!!' ; ret}

  ruby = dsl.ruby
  dsl.watch_spec_files_for(ruby.lib_files)
end
