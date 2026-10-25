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
      # Thread safe cache to store AWS credentials.
      #
      # @api private
      class CredentialsCache
        # Get or create the singleton instance of the cache.
        #
        # @return [ CredentialsCache ] The singleton instance.
        def self.instance
          @instance ||= new
        end

        # Callers queued behind a failed fetch fail fast for this long instead of each retrying the endpoint.
        FAILURE_BACKOFF_SECONDS = 1

        def initialize
          @lock = Mutex.new
          @refresh_lock = Mutex.new
          @credentials = nil
          @failed_at = nil
        end

        # Set the credentials in the cache.
        #
        # @param [ Aws::Credentials ] credentials The credentials to cache.
        def credentials=(credentials)
          @lock.synchronize do
            @credentials = credentials
          end
        end

        # Get the credentials from the cache.
        #
        # @return [ Aws::Credentials ] The cached credentials.
        def credentials
          @lock.synchronize do
            @credentials
          end
        end

        # Fetch the credentials from the cache or yield to get them
        # if they are not in the cache or have expired.
        #
        # One caller refreshes at a time; the rest keep using still-usable credentials instead of waiting.
        #
        # @return [ Aws::Credentials ] The cached credentials.
        def fetch(&block)
          current = credentials
          return current if current && !current.expired?

          if current&.usable?
            return current unless @refresh_lock.try_lock

            begin
              refresh_keeping_cached(&block)
            ensure
              @refresh_lock.unlock
            end
          else
            @refresh_lock.synchronize do
              current = credentials
              next current if current && !current.expired?

              self.credentials = attempt(&block)
            end
          end
        end

        # Clear the credentials from the cache.
        def clear
          @lock.synchronize do
            @credentials = nil
          end
        end

        private

        # Runs under @refresh_lock. Callers arriving within the backoff after a failure skip the endpoint.
        def attempt
          return nil if @failed_at && Utils.monotonic_time - @failed_at < FAILURE_BACKOFF_SECONDS

          fetched = yield
          @failed_at = fetched.nil? ? Utils.monotonic_time : nil
          fetched
        end

        # Re-reads the cache rather than a snapshot so a concurrent refresh or clear is honored.
        def refresh_keeping_cached(&block)
          current = credentials
          return current if current && !current.expired?

          refreshed = begin
            attempt(&block)
          rescue Auth::InvalidConfiguration
            # A malformed agent response is a failed refresh here; it resurfaces once the cached set is unusable.
            @failed_at = Utils.monotonic_time
            nil
          end
          if refreshed.nil?
            current = credentials
            return current&.usable? ? current : nil
          end

          self.credentials = refreshed
        end
      end
    end
  end
end
