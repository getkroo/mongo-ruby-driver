# frozen_string_literal: true

require 'lite_spec_helper'
require 'tempfile'

describe Mongo::Auth::Aws::CredentialsRetriever do
  context 'when a refresh from another credential source fails' do
    let(:cache) { Mongo::Auth::Aws::CredentialsCache.new }
    let(:retriever) { described_class.new(nil, credentials_cache: cache) }
    let(:token_file) { Tempfile.new('web-identity-token').tap { |f| f.write('token').tap { f.flush } } }

    around do |example|
      keys = %w[AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
                AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI]
      saved = keys.to_h { |k| [ k, ENV.fetch(k, nil) ] }
      keys.each { |k| ENV.delete(k) }
      example.run
    ensure
      saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
      token_file.close!
    end

    before do
      cache.credentials = Mongo::Auth::Aws::Credentials.new('ASIAOLD', 'old', 'old-token', Time.now.utc + 240)
      imds = instance_double(Net::HTTP, request: double('response', code: '404'))
      allow(Net::HTTP).to receive(:new).with('169.254.169.254').and_return(imds)
    end

    it 'keeps still-usable credentials when the web identity STS call times out' do
      ENV['AWS_WEB_IDENTITY_TOKEN_FILE'] = token_file.path
      ENV['AWS_ROLE_ARN'] = 'arn:aws:iam::123456789012:role/app'
      allow(Net::HTTP).to receive(:start).and_raise(Net::OpenTimeout)

      expect(retriever.credentials.access_key_id).to eq('ASIAOLD')
    end

    it 'keeps still-usable credentials when the ECS endpoint returns malformed JSON' do
      ENV['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'] = '/v2/credentials'
      http = instance_double(Net::HTTP, request: double('response', code: '200', body: 'not json'))
      allow(Net::HTTP).to receive(:new).with('169.254.170.2').and_return(http)

      expect(retriever.credentials.access_key_id).to eq('ASIAOLD')
    end
  end
end
