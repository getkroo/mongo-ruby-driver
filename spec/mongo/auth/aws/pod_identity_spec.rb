# frozen_string_literal: true

require 'lite_spec_helper'
require 'support/fake_pod_identity_agent'
require 'tempfile'

describe Mongo::Auth::Aws::CredentialsRetriever do
  context 'with EKS Pod Identity' do
    let(:agent) { FakePodIdentityAgent.new }
    let(:token_file) { Tempfile.new('pod-identity-token').tap { |f| f.write("token-v1\n").tap { f.flush } } }
    let(:cache) { Mongo::Auth::Aws::CredentialsCache.new }
    let(:retriever) { described_class.new(nil, credentials_cache: cache) }

    around do |example|
      keys = %w[AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE
                AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI
                AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE AWS_CONTAINER_AUTHORIZATION_TOKEN http_proxy HTTP_PROXY]
      saved = keys.to_h { |k| [ k, ENV.fetch(k, nil) ] }
      keys.each { |k| ENV.delete(k) }
      ENV['AWS_CONTAINER_CREDENTIALS_FULL_URI'] = agent.url
      ENV['AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE'] = token_file.path
      example.run
    ensure
      saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
      agent.stop
      token_file.close!
    end

    it 'fetches credentials from the agent with the rotating token from the token file' do
      first = retriever.credentials
      expect(first.access_key_id).to eq('ASIAFAKE1')
      expect(first.session_token).to eq('session-1')
      expect(first.expiration).to be > Time.now + 3000

      File.write(token_file.path, "token-v2\n")
      cache.clear
      retriever.credentials

      expect(Array.new(agent.request_count) { agent.requests.pop }.map(&:authorization))
        .to eq(%w[token-v1 token-v2])
    end

    it 'fails fast instead of falling back to the instance role when the agent is down' do
      agent.status = 500
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      expect { retriever.credentials }.to raise_error(Mongo::Auth::Aws::CredentialsNotFound)
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1
    end

    it 'treats a malformed agent payload as no credentials' do
      [
        'null',
        '[]',
        '{"AccessKeyId":"ASIANEW"}',
        '{"AccessKeyId":"ASIANEW","SecretAccessKey":"new","Token":"new-token","Expiration":"not a time"}',
      ].each do |body|
        agent.raw_body = body
        cache.clear

        expect { retriever.credentials }.to raise_error(Mongo::Auth::Aws::CredentialsNotFound), body
      end
    end

    it 'refuses plain-http hosts other than loopback and the container agents' do
      ENV['AWS_CONTAINER_CREDENTIALS_FULL_URI'] = 'http://attacker.example.com/creds'
      expect { retriever.credentials }.to raise_error(Mongo::Auth::InvalidConfiguration, /must use https/)

      ENV['AWS_CONTAINER_CREDENTIALS_FULL_URI'] = 'http://10.0.0.5/creds'
      expect { retriever.credentials }.to raise_error(Mongo::Auth::InvalidConfiguration)
    end

    # Ruby never proxies loopback, so a loopback agent cannot show the leak; check the client's proxy setting instead.
    it 'ignores an http_proxy in the environment so the token never leaves the host' do
      ENV['http_proxy'] = 'http://proxy.example.com:3128/'
      clients = []
      allow(Net::HTTP).to receive(:start).and_wrap_original do |start, *args, &block|
        start.call(*args) do |http|
          clients << http
          block.call(http)
        end
      end

      expect(retriever.credentials.access_key_id).to eq('ASIAFAKE1')
      expect(clients.map(&:proxy_from_env?)).to eq([ false ])
    end

    it 'refuses a token that would inject a header' do
      File.write(token_file.path, "token\r\nX-Evil: 1")
      expect { retriever.credentials }.to raise_error(Mongo::Auth::InvalidConfiguration, /line break/)
    end

    it 'makes one agent request for a cold cache, however many handshakes race' do
      results = Array.new(200) { Thread.new { retriever.credentials } }.map(&:value)

      expect(agent.request_count).to eq(1)
      expect(results.map(&:access_key_id).uniq).to eq(%w[ASIAFAKE1])
    end
  end
end
