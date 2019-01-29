# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"

# Rocket.Chat is free, unlimited and open source. Replace email, HipChat & Slack with the ultimate team chat software solution.
#
# This Logstash output plugin allows to send events as messages to channels and groups of a Rocketchat server.
#
# ==== Example
#
# [source,ruby]
# ----------------------------------
# input {
#   stdin { } 
# }
# output {
#   rocketchat {
#     host => "chat.deathstar.sw"
#     port => "3000"
#     username => "rc_integrations"
#     password => "p@$$w0rd"
#     channels => ["management", "operations", "rh"]
#   }
# }
# ----------------------------------
#


# An rocketchat output that does nothing.
class LogStash::Outputs::Rocketchat < LogStash::Outputs::Base
  config_name "rocketchat"

  # Host address of the Rocketchat server
  config :host, :validate => :string, :required => true

  # Port in which the Rocketchat server is listening
  config :port, :validate => :string,:default => 3000

  # Http or https
  config :scheme, :validate => :string, :default => "http"

  # API route
  config :api, :validate => :string, :default => "/api/v1"

  # Username to use for the integration
  config :username, :validate => :string, :required => true

  # Password of the user
  config :password, :validate => :string, :required => true

  # A list of channels/groups to which the messages will be posted 
  config :channels, :validate => :string, :required => true, :list => true

  # Format of the message (content)
  config :format, :validate => :string, :default => "%{message}"

  concurrency :single

  public
  def register
	  m = __method__.to_s

    require 'rest-client'
    require 'cgi'
    require 'json'
	
	  raw_url = "#{@scheme}://#{@host}:#{@port}#{@api}"
	  @url = ::LogStash::Util::SafeURI.new(raw_url)

	  @logger.info("[#{m}] URL #{@url}, Username: #{@username}, Channel: #{@channels}")

    auth()
  end # def register

  public
  def receive(event)
	  return unless output?(event)

    m = __method__.to_s

    message = event.sprintf(@format)

    @channels.map {|channel|
      if send_message(channel, message)
        @logger.debug("[#{m}] Message sent to room #{channel}")
      else
        @logger.error("[#{m}] An error occurred trying to send a message to room #{channel}.")
      end
    }

  end # def event

  public
  def auth()
	  m = __method__.to_s

	  @logger.debug("[i#{m}] Trying to authenticate")

    endpoint = "#{@url}/login"

    payload = Hash.new
    payload['username'] = @username 
    payload['password'] = @password 

	  @logger.debug("[#{m}] Endpoint: #{endpoint}, payload: #{payload}")

    body = make_request('POST', endpoint, nil, payload)

	  if body.nil?
      @logger.error("[#{m}] An error occurred trying to authenticate to the Rocketchat server")
	    return false
	  else
      status = body['status']
	    if status == 'success'
        @userId = body['data']['userId']
        @authToken = body['data']['authToken']
	      return true
	    end
    end
  end # def auth

  public
  def get_room_id(room_name)
	  m = __method__.to_s

	  @logger.debug("[#{m}] Trying to get the room id for room #{room_name}")
  
    endpoint = "#{@url}/channels.info"
	  body = make_request('GET', endpoint, {:roomName => room_name}, nil)

	  if body.nil?
      @logger.error("[#{m}] An error occurred trying to get the room id (channels endpoint) for room #{room_name}")
	  else
	    success = body['success']
      if success
	      return body['channel']['_id']
		  else
        @logger.info("[#{m}] Couldn't get the room id for room #{room_name} through the channels endpoint, trying with the groups endpoint")

        endpoint = "#{@url}/groups.info"
	      body = make_request('GET', endpoint, {:roomName => room_name}, nil)

		    if body.nil?
        	@logger.error("[#{m}] An error occurred trying to get the room id (groups endpoint) for room #{room_name}")
		    else
		      success = body['success']
			    if success
		  	    return body['group']['_id']
			    else
			      return nil
			    end
		    end	  
		  end
    end

    return nil
  end # def get_room_id

  public
  def send_message(room_name, message)
	  m = __method__.to_s

	  @logger.debug("[#{m}] Trying to send message to room #{room_name}")
  
    endpoint = "#{@url}/chat.sendMessage"

    room_id = get_room_id(room_name)

    if room_id
      payload = Hash.new
      payload['message'] = Hash.new
      payload['message']['rid'] = room_id 
      payload['message']['msg'] = message
  
      body = make_request('POST', endpoint, nil, payload)
  
      if body.nil?
        @logger.error("[#{m}] An error occurred trying to send message to the Rocketchat server, room #{room_name}")
        return false
      else
        status = body['status']
        if status == 'success'
          return true
        end
      end      
    else
      @logger.warn("[#{m}] An error occurred trying to get the room id for room #{room_name}. Are you sure the user #{@user} is sunscripted to this room?")
    end
    
    return nil
  end # def send_message

  public
  def make_request(method, endpoint, params = nil, payload = nil)
	  m = __method__.to_s

	  @logger.debug("[#{m}] Making a #{method} request to #{endpoint}")
	  @logger.debug("[#{m}] Auth token: #{@authToken}")
    @logger.debug("[#{m}] User id: #{@userId}")
    @logger.debug("[#{m}] Params: #{params}")
    @logger.debug("[#{m}] Payload: #{payload}")

    begin
      if method == 'POST'
        RestClient.post(
          endpoint,
          JSON.dump(payload),
          {
            :'X-Auth-Token' => @authToken || '',
            :'X-User-Id' => @userId || '' ,
            :accept => "application/json",
            :'User-Agent' => "logstash-output-rocketchat",
            :content_type => @content_type
          }) { |response, request, result, &block|
            if response.code != 200
              @logger.error("[#{m}] An error occurred trying to request from the Rocketchat's server API: #{response.code}")
              @logger.debug("[#{m}] Got a #{response.code} response: #{response}")

              return response.body ? JSON.parse(response.body) : nil
		        else
              @logger.debug("[#{m}] Got a #{response.code} response: #{response}")

              return response.body ? JSON.parse(response.body) : nil
            end
          }
      elsif method == 'GET'
        RestClient.get(
          endpoint,
		      {
          	:params => params,
			      :'X-Auth-Token' => @authToken || '',
		  	    :'X-User-Id' => @userId || '' ,
          	:accept => "application/json",
          	:'User-Agent' => "logstash-output-rocketchat",
          	:content_type => @content_type
		      }) { |response, request, result, &block|
            if response.code != 200
              @logger.error("[#{m}] An error occurred trying to request from the Rocketchat's server API: #{response.code}")
              @logger.debug("[#{m}] Got a #{response.code} response: #{response}")

              return response.body ? JSON.parse(response.body) : nil
		        else
              @logger.debug("[#{m}] Got a #{response.code} response: #{response}")

              return response.body ? JSON.parse(response.body) : nil
            end
	      }
      end
    rescue Exception => e
      @logger.error("[#{m}] Unhandled exception", :exception => e, :stacktrace => e.backtrace)
    end
  end # def make_request
end # class LogStash::Outputs::Rocketchat
