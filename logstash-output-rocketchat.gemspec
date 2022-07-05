Gem::Specification.new do |s|
  s.name          = 'logstash-output-rocketchat'
  s.version       = '0.1.4'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Sends messages to a Rocketchat server with information from the events.'
  s.description   = 'Rocket.Chat is the leading open source team chat software solution. Free, unlimited and completely customizable with on-premises and SaaS cloud hosting. This Logstash plugin allows to send events to Rocketchat channels and groups.' 
  s.homepage      = 'https://github.com/ffknob/logstash-output-rocketchat'
  s.authors       = ['ffknob']
  s.email         = 'ffknob@tce.rs.gov.br'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "output" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"
  s.add_runtime_dependency "logstash-codec-plain"
  s.add_runtime_dependency "rest-client", '~> 1.8', ">= 1.8.0"
  s.add_development_dependency "logstash-devutils"
  s.add_development_dependency "logstash-filter-json"
end
