# encoding: utf-8
require "logstash/outputs/base"

# An rocketchat output that does nothing.
class LogStash::Outputs::Rocketchat < LogStash::Outputs::Base
  config_name "rocketchat"

  config :host, :validate => :string, :required => true
  config :port, :validate => :string,:default => 3000
  config :scheme, :validate => :string, :default => "http"
  config :api_endpoint, :validate => :string, :default => "/api/v1/"
  config :username, :validate => :string, :required => true
  config :password, :validate => :password, :required => true
  config :channels, :validate => :string, :required => true, :list => true

  concurrency :single

  public
  def register
    require 'rest-client'
    require 'cgi'
    require 'json'
  end # def register

  public
  def receive(event)
	return unless output?(event)

	raw_url = "#{@scheme}://#{@host}:#{@port}#{@api_endpoint}"
	url = ::LogStash::Util::SafeURI.new(raw_url)

	@logger.info("URL #{url}, Username: #{username}, Channel: #{channels}")

  end # def event
end # class LogStash::Outputs::Rocketchat
