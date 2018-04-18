# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/private_geo_ip"

describe LogStash::Filters::PrivateGeoIp do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        private_geo_ip {
          source => "ip"
        }
      }
    CONFIG
    end

    sample("ip" => "some text") do
      # expect(subject).to include("message")
      expect(subject.get('geoip')).to eq('Hello World')
    end
  end
end
