# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'csv'
# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::PrivateGeoIp < LogStash::Filters::Base

  config_name "private_geo_ip"
  
  # The path to the GeoLite2 database file which Logstash should use. City and ASN databases are supported.
  #
  # If not specified, this will default to the GeoLite2 City database that ships
  # with Logstash.
  config :db_path, :validate => :path, :required => true
  # The field containing the IP address or hostname to map via geoip. If
  # this field is an array, only the first value will be used.
  config :source, :validate => :string, :required => true

   # Even if you don't use the `geo_point` mapping, the `[target][location]` field
  # is still valid GeoJSON.
  config :target, :validate => :string, :default => 'geoip'

  # Tags the event on failure to look up geo information. This can be used in later analysis.
  config :tag_on_failure, :validate => :array, :default => ["_ip_lookup_failure"]
  config :fields, :validate => :array, :default => ['country','city','region','postalCode','latitude','longitude','site']

  public
  def register
    if !File.exists?(@db_path)
      raise "You must specify 'database => ...' in your geoip filter (I looked for '#{@db_path}')"
    end
    @geoipfilter = []
    @logger.info("Using private network path", :path => @db_path)
  end # def register

  public
  def filter(event)

    filtered_row = nil
    inputIp = @source.split('.').map(&:to_i)
    @logger.info("source IP",:string => @source)
    #puts ipArray
    inputIpInt = inputIp[0].to_i   * 16777216 + inputIp[1].to_i   * 65536  + inputIp[2].to_i   * 256 + inputIp[3].to_i  
    @logger.info("source IP Int",:int => inputIpInt)
    CSV.foreach(@db_path, :headers => true) do |row|
      ipArray = row['endip'].split('.')
      endIpInt = ipArray[0].to_i   * 16777216 + ipArray[1].to_i   * 65536  + ipArray[2].to_i   * 256 + ipArray[3].to_i 
      ipArray = row['startip'].split('.').map(&:to_i) 
      startIpInt = ipArray[0].to_i   * 16777216 + ipArray[1].to_i   * 65536  + ipArray[2].to_i   * 256 + ipArray[3].to_i  
      if inputIpInt <= endIpInt and inputIpInt >= startIpInt
        filtered_row = row
      end
    end
    @logger.info("filtered_row",filtered_row)
    if filtered_row.nil?
      String s = "[" + target + "][";
      @fields.each do |f|
        event.set(s + f + "]", filtered_row[f]);
      end 
      # filter_matched should go in the last line of our successful code
      filter_matched(event)
    else
      tag_unsuccessful_lookup(event);
    end
  end # def filter
  def tag_unsuccessful_lookup(event)
    @logger.debug? && @logger.debug("IP #{event.get(@source)} was not found in the database", :event => event)
    @tag_on_failure.each{|tag| event.tag(tag)}
  end #def tag_unsuccessfull_lookup
end # class LogStash::Filters::PrivateGeoIp
