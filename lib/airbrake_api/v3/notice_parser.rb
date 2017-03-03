require "open-uri"
require "execjs"
module AirbrakeApi
  module V3
    class NoticeParser
      class ParamsError < StandardError; end

      attr_reader :params, :error

      def initialize(params)
        @params = params || {}
      end

      def attributes
        {
          error_class:        error['type'],
          message:            error['message'],
          backtrace:          backtrace,
          request:            request,
          server_environment: server_environment,
          api_key:            params['key'].present? ? params['key'] : params['project_id'],
          notifier:           context['notifier'] || params['notifier'],
          user_attributes:    user_attributes
        }
      end

      def report
        ErrorReport.new(attributes)
      end

    private

      def error
        fail AirbrakeApi::ParamsError unless params.key?('errors') && params['errors'].any?
        @error ||= params['errors'].first
      end

      def backtrace
        (error['backtrace'] || []).map do |backtrace_line|
          event = {
            method: backtrace_line['function'],
            file:   backtrace_line['file'],
            number: backtrace_line['line'],
            column: backtrace_line['column']
          }
          if context['sourceMapEnabled']
            event = resolve_source_maps(event)
          end
          event
        end
      end

      def server_environment
        {
          'environment-name' => context['environment'],
          'hostname'         => hostname,
          'project-root'     => context['rootDirectory'],
          'app-version'      => context['version']
        }
      end

      def request
        environment = (params['environment'] || {}).merge(
          'HTTP_USER_AGENT' => context['userAgent']
        )

        {
          'cgi-data'  => environment,
          'session'   => params['session'],
          'params'    => params['params'],
          'url'       => url,
          'component' => context['component'],
          'action'    => context['action']
        }
      end

      def user_attributes
        return context['user'] if context['user']

        {
          'id'       => context['userId'],
          'name'     => context['userName'],
          'email'    => context['userEmail'],
          'username' => context['userUsername']
        }.compact
      end

      def url
        context['url']
      end

      def hostname
        context['hostname'] || URI.parse(url).hostname
      rescue URI::InvalidURIError
        ''
      end

      def context
        @context = params['context'] || {}
      end

      def resolve_source_maps(event)
        if source_map_for?(event[:file])
          begin
            code = "(new sourceMap.SourceMapConsumer(#{source_map_for(event[:file])})).originalPositionFor({line: #{event[:number]}, column: #{event[:column]}})"
            position = source_map_parser.eval(code)
            if position['line'] && position['column'] && position['source']
              event[:number] = position['line']
              event[:column] = position['column']
              event[:file] = position['source']
            end
          rescue => e
            HoptoadNotifier.notify(e)
          end
        end
        event
      end

      def source_map_for?(file)
        context['sourceMaps'][file].present?
      end

      def source_map_for(file)
        map = context['sourceMaps'][file]
        @source_maps ||= {}
        @source_maps[file] ||= begin
          begin
            Rails.cache.fetch(map) do
              open(map).read.force_encoding(Encoding::UTF_8).encode
            end
          rescue => e
            HoptoadNotifier.notify(e)
            "{version:3,sources:[],mappings:[]}"
          end
        end
      end

      def source_map_parser
        @source_map_parser ||= begin
          source = File::join(Rails.root, 'lib', 'mozilla_source_map', 'source-map.min.js')
          ExecJS.compile(File::read(source))
        end
      end
    end
  end
end
