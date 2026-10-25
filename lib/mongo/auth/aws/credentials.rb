# frozen_string_literal: true

# Copyright (C) 2023-present MongoDB Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module Mongo
  module Auth
    class Aws
      # The AWS credential set.
      #
      # @api private
      Credentials = Struct.new(:access_key_id, :secret_access_key, :session_token, :expiration) do
        # @return [ true | false ] Whether the credentials have expired.
        def expired?
          if expiration.nil?
            false
          else
            # According to the spec, Credentials are considered
            # valid if they are more than five minutes away from expiring.
            Time.now.utc >= expiration - 300
          end
        end

        # Whether the credentials can still sign a handshake, even if due for refresh.
        #
        # @return [ true | false ]
        def usable?
          expiration.nil? || Time.now.utc < expiration - 30
        end

        # Keeps the secret and session token out of logs and error output.
        def inspect
          "#<#{self.class.name} access_key_id=#{access_key_id.inspect} expiration=#{expiration.inspect}>"
        end
        alias_method :to_s, :inspect
      end
    end
  end
end
