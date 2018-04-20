# encoding: utf-8

require 'spec_helper'
require "logstash/patterns/core"

# solution based on https://github.com/logstash-plugins/logstash-filter-grok/blob/master/spec/filters/grok_spec.rb
module LogStash::Environment
  # running the grok code outside a logstash package means
  # LOGSTASH_HOME will not be defined, so let's set it here
  # before requiring the grok filter

  # the path that is set is the plugin root path
  unless self.const_defined?(:LOGSTASH_HOME)
    LOGSTASH_HOME = File.expand_path("../../../", __FILE__)
  end

  # also :pattern_path method must exist so we define it too

  # method is called by logstash-filter-grok to create patterns_path array
  #
  #   logstash-filter-grok/lib/logstash/filters/grok.rb(line ~230):
  #
  #   @@patterns_path += [
  #     LogStash::Patterns::Core.path,
  #     LogStash::Environment.pattern_path("*")
  #
  # patterns defined in spec/patterns/ will be joined to the array by the grok 

  unless self.method_defined?(:pattern_path)
    def pattern_path(path)
      ::File.join(LOGSTASH_HOME, "spec", "patterns", path)
    end
  end
end

require "logstash/filters/grok"
require "logstash/filters/private_geo_ip"

describe "LogStash::Filters::PrivateGeoIp" do
  describe "apache log" do

    let(:config) do <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{IP:source}: %{DATA}: %{DATA:header_field1}: %{GREEDYDATA:header_field2}" }
        }
        private_geo_ip {
          source => "10.10.29.25"
          db_path => "C:/GFApps/elastic/logstash-filter-private-geo-ip/private_loc_details.csv"
        }
      }
      CONFIG
    end
    
    describe "Decode valid messages" do

      message = "10.10.25.24: Example mail header field: =?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?==?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=: =?ISO-8859-2?B?VGhlIHNlY29uZCBtZXNzYWdl=?="

      sample ({
                'message' => message,
                'type' => 'type'
      }) do
        insist { subject.get("geoip")} == "If you can read this you understand the example."
      end
    end

    describe "Invalid message should pass through unchanged" do

      message = "2013-01-20T13:14:01+0000: Example mail header field: =?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?==?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=: =?iso-2022-jp?Q?whatever"

      sample ({
                'message' => message,
                'type' => 'type'
      }) do
        insist { subject.get("geoip") } == "If you can read this you understand the example."
      end
    end

  end
end
