# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::PrivateGeoIp < LogStash::Filters::Base

  config_name "private_geo_ip"
  
  # Replace the message with this value.
  config :source, :validate => :string, :default => "127.0.0.1"
  
  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)

    puts("default:"+@source)
    puts event
    ip = 10
    event.set("geoip", @ip)
    
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::PrivateGeoIp
