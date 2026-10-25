# frozen_string_literal: true

require 'socket'
require 'json'
require 'time'

# Stands in for the EKS Pod Identity agent: serves container credentials
# JSON on loopback and records every request it receives.
class FakePodIdentityAgent
  Request = Struct.new(:path, :authorization)

  attr_reader :requests
  attr_accessor :delay, :status, :credentials

  def initialize(credentials: nil, ttl: 3600)
    @server = TCPServer.new('127.0.0.1', 0)
    @requests = Queue.new
    @delay = 0
    @status = 200
    @ttl = ttl
    @credentials = credentials
    @issued = 0
    @thread = Thread.new { serve }
  end

  def url
    "http://127.0.0.1:#{@server.addr[1]}/v1/credentials"
  end

  def request_count
    @requests.size
  end

  def stop
    @thread.kill
    @server.close
  end

  private

  def serve
    loop do
      socket = @server.accept
      Thread.new(socket) { |s| handle(s) }
    end
  end

  def handle(socket)
    request_line = socket.gets.to_s
    headers = {}
    while (line = socket.gets) && line != "\r\n"
      name, value = line.split(':', 2)
      headers[name.downcase] = value.strip
    end
    @requests << Request.new(request_line.split[1], headers['authorization'])
    sleep(delay) if delay.positive?
    body = (status == 200) ? JSON.generate(payload) : '{"message":"unavailable"}'
    socket.write("HTTP/1.1 #{status} X\r\nContent-Type: application/json\r\n" \
                 "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
  ensure
    socket.close
  end

  def payload
    @issued += 1
    creds = credentials || {
      'AccessKeyId' => "ASIAFAKE#{@issued}",
      'SecretAccessKey' => "secret-#{@issued}",
      'Token' => "session-#{@issued}",
    }
    { 'Expiration' => (Time.now.utc + @ttl).iso8601 }.merge(creds)
  end
end
