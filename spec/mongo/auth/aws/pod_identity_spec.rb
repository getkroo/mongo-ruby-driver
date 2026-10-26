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
      expect(first.inspect).not_to include('secret-1', 'session-1')

      File.write(token_file.path, "token-v2\n")
      cache.clear
      retriever.credentials

      expect(Array.new(agent.request_count) { agent.requests.pop }.map(&:authorization))
        .to eq(%w[token-v1 token-v2])
    end

    it 'does not fall back to the instance metadata endpoint when the agent is down' do
      agent.status = 500
      hosts = []
      allow(Net::HTTP).to receive(:new).and_wrap_original do |new, address, *args|
        hosts << address
        new.call(address, *args)
      end

      expect { retriever.credentials }.to raise_error(Mongo::Auth::Aws::CredentialsNotFound)
      expect(hosts).not_to include('169.254.169.254')
    end

    it 'does not make every queued handshake wait out its own timeout when the agent hangs' do
      stub_const('Mongo::Auth::Aws::CredentialsRetriever::CONTAINER_AGENT_TIMEOUT', 0.3)
      agent.delay = 1
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      outcomes = Array.new(20) do
        Thread.new do
          retriever.credentials
        rescue Mongo::Auth::Aws::CredentialsNotFound
          :not_found
        end
      end.map(&:value)

      expect(outcomes.uniq).to eq([ :not_found ])
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1.5
    end

    it 'rejects a payload with an empty or non-string field instead of caching credentials that cannot sign' do
      expiration = (Time.now.utc + 3600).iso8601
      [
        %({"AccessKeyId":"ASIANEW","SecretAccessKey":"","Token":"new-token","Expiration":"#{expiration}"}),
        %({"AccessKeyId":12345,"SecretAccessKey":"new","Token":"new-token","Expiration":"#{expiration}"}),
      ].each do |body|
        agent.raw_body = body
        cache.clear

        expect { retriever.credentials }.to raise_error(Mongo::Auth::InvalidConfiguration, /without/), body
        expect(cache.credentials).to be_nil
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

    context 'under concurrent connection handshakes' do
      let(:threads) { 200 }

      it 'makes one agent request for a cold cache, however many handshakes race' do
        results = Array.new(threads) { Thread.new { retriever.credentials } }.map(&:value)

        expect(agent.request_count).to eq(1)
        expect(results.map(&:access_key_id).uniq).to eq(%w[ASIAFAKE1])
      end

      it 'serves still-usable credentials without waiting while one handshake refreshes' do
        cache.credentials = Mongo::Auth::Aws::Credentials.new('ASIAOLD', 'old', 'old-token', Time.now.utc + 240)
        agent.delay = 1.5

        timings = Array.new(threads) do
          Thread.new do
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            creds = retriever.credentials
            [ creds.access_key_id, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started ]
          end
        end.map(&:value)

        waited = timings.count { |(_, seconds)| seconds > 1 }
        expect(waited).to eq(1)
        expect(timings.reject { |(_, seconds)| seconds > 1 }.map(&:last).max).to be < 0.5
        expect(agent.request_count).to eq(1)
        expect(retriever.credentials.access_key_id).to eq('ASIAFAKE1')
      end

      it 'keeps still-usable credentials when the agent fails during refresh' do
        cache.credentials = Mongo::Auth::Aws::Credentials.new('ASIAOLD', 'old', 'old-token', Time.now.utc + 240)
        agent.status = 500

        results = Array.new(threads) { Thread.new { retriever.credentials } }.map(&:value)

        expect(results.map(&:access_key_id).uniq).to eq(%w[ASIAOLD])
      end

      it 'keeps still-usable credentials when the agent returns a malformed payload' do
        bodies = [
          'null',
          '[]',
          '{"AccessKeyId":"ASIANEW"}',
          '{"AccessKeyId":"ASIANEW","SecretAccessKey":"new","Token":"new-token","Expiration":"not a time"}',
          %({"AccessKeyId":"ASIANEW","Token":"new-token","Expiration":"#{(Time.now.utc + 3600).iso8601}"}),
        ]
        bodies.each do |body|
          cache = Mongo::Auth::Aws::CredentialsCache.new
          cache.credentials = Mongo::Auth::Aws::Credentials.new('ASIAOLD', 'old', 'old-token', Time.now.utc + 240)
          agent.raw_body = body

          expect(described_class.new(nil, credentials_cache: cache).credentials.access_key_id).to eq('ASIAOLD'), body
        end
        expect(agent.request_count).to eq(bodies.size)
      end

      it 'stops retrying a failing agent for a moment while serving usable credentials' do
        cache.credentials = Mongo::Auth::Aws::Credentials.new('ASIAOLD', 'old', 'old-token', Time.now.utc + 240)
        agent.status = 500

        2.times { expect(retriever.credentials.access_key_id).to eq('ASIAOLD') }

        expect(agent.request_count).to eq(1)
      end

      it 'does not sign with credentials that crossed the expiry margin during a failed refresh' do
        cache.credentials = Mongo::Auth::Aws::Credentials.new('ASIAOLD', 'old', 'old-token', Time.now.utc + 31)
        agent.status = 500
        agent.delay = 1.5

        expect { retriever.credentials }.to raise_error(Mongo::Auth::Aws::CredentialsNotFound)
      end

      it 'does not resurrect credentials the server rejected while a refresh was failing' do
        cache.credentials = Mongo::Auth::Aws::Credentials.new('ASIAOLD', 'old', 'old-token', Time.now.utc + 240)
        agent.status = 500
        agent.hold = Queue.new

        refreshing = Thread.new { retriever.credentials }
        refreshing.report_on_exception = false
        agent.requests.pop
        cache.clear
        agent.hold << :respond

        expect { refreshing.value }.to raise_error(Mongo::Auth::Aws::CredentialsNotFound)
      end
    end
  end
end
