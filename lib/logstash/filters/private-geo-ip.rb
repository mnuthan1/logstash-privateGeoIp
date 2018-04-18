# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::PrivateGeoIp < LogStash::Filters::Base

  config_name "private-geo-ip"
  
  # Replace the message with this value.
  config :message, :validate => :string, :default => "Hello World!"
  config :ip, :validate=> :string, :default=> "0.0.0.0"

  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)
    puts("Message is now: #{event.get("message")}")
    if @message
      # Replace the event message with our message as configured in the
      # config file.
      
      puts event.get("source")
      event.set("geoIp", @message)
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::PrivateGeoIp
