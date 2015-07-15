## Copyright 2015, Yahoo! Inc.
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'rtrace'
  spec.version    = '1.4'
  spec.author     = 'Chris Rohlf'
  spec.license    = 'BSD'
  spec.email      = 'chrisrohlf@yahoo-inc.com'
  spec.summary    = 'Rtrace is a native code debugger written in Ruby'
  spec.files      = Dir['**/*'].delete_if{ |item| item.include?('git') }
  spec.extra_rdoc_files = [ 'README.md' ]
  spec.add_runtime_dependency 'ffi'
  spec.description = "Rtrace is a native code debugger written in Ruby."
end
