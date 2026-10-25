# frozen_string_literal: true

require 'lite_spec_helper'

describe Mongo::Auth::Aws do
  describe '#login' do
    let(:cache) { Mongo::Auth::Aws::CredentialsCache.instance }
    let(:credentials) { Mongo::Auth::Aws::Credentials.new('ASIACACHED', 'secret', 'token', Time.now.utc + 3600) }
    let(:user) { Mongo::Auth::User.new(auth_mech: :aws) }
    let(:auth) { described_class.new(user, double('connection')) }

    before do
      cache.credentials = credentials
    end

    after do
      cache.clear
    end

    it 'keeps the cached credentials when the handshake fails before the server answers' do
      allow(auth).to receive(:converse_2_step).and_raise(Mongo::Error::SocketError, 'connection reset')

      expect { auth.login }.to raise_error(Mongo::Error::SocketError)
      expect(cache.credentials).to eq(credentials)
    end

    it 'drops the cached credentials when the server rejects them' do
      allow(auth).to receive(:converse_2_step).and_raise(Mongo::Auth::Unauthorized.new(user))

      expect { auth.login }.to raise_error(Mongo::Auth::Unauthorized)
      expect(cache.credentials).to be_nil
    end
  end
end
