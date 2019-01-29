# encoding: utf-8
require "logstash/outputs/base"

# An rocketchat output that does nothing.
class LogStash::Outputs::Rocketchat < LogStash::Outputs::Base
  config_name "rocketchat"

  config :host, :validate => :string, :required => true
  config :port, :validate => :string,:default => 3000
  config :scheme, :validate => :string, :default => "http"
  config :api, :validate => :string, :default => "/api/v1"
  config :username, :validate => :string, :required => true
  config :password, :validate => :string, :required => true
  config :channels, :validate => :string, :required => true, :list => true

  concurrency :single

  public
  def register
    require 'rest-client'
    require 'cgi'
    require 'json'
	
	raw_url = "#{@scheme}://#{@host}:#{@port}#{@api}"
	@url = ::LogStash::Util::SafeURI.new(raw_url)

	@logger.info("[receive] URL #{@url}, Username: #{@username}, Channel: #{@channels}")

    auth()
  end # def register

  public
  def receive(event)
	return unless output?(event)



  end # def event

  public
  def auth()
	@logger.debug("[auth] Trying to authenticate")

    endpoint = "#{@url}/login"

    payload = Hash.new
    payload['username'] = @username 
    payload['password'] = @password 

	@logger.debug("[auth] Endpoint: #{endpoint}, payload: #{payload}")

    body = make_request(endpoint, payload)

	if body.nil?
      @logger.error("[auth] An error occurred trying to authenticate to the Rocketchat server")

	  return false
	else
      status = body['status']
	  if status == 'success'
        @userId = body['data']['userId']
        @authToken = body['data']['authToken']

	    return true
	  end
    end
  end

  public
  def make_request(endpoint, payload)
	@logger.debug("[make_request] Making a request to the Rocketchat server")

    begin
      RestClient.post(
        endpoint,
        JSON.dump(payload),
        :accept => "application/json",
        :'User-Agent' => "logstash-output-rocketchat",
        :content_type => @content_type) { |response, request, result, &block|
		  @logger.debug("[make_request] request response")

          if response.code != 200
            @logger.error("[make_request] Couldn't authentication to the Rocketchat server. Wrong username/password?")
            @logger.debug("[make_request] Got a #{response.code} response: #{response}")

			return nil
		  else
            @logger.debug("[make_request] Got a #{response.code} response: #{response}")

			body = JSON.parse(response.body)

			return body
          end
        }
    rescue Exception => e
      @logger.error("[make_request] Unhandled exception", :exception => e,
                   :stacktrace => e.backtrace)
    end
  end
end # class LogStash::Outputs::Rocketchat
