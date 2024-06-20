%%%-------------------------------------------------------------------
%% @doc we parse command line args here
%% @end
%%%-------------------------------------------------------------------

-module(decent).

-export([main/1]).

main(Args) ->
    argparse:run(Args, cli(), #{progname => decent}).

cli() -> #{
        arguments => [
            #{name => port, type => integer, long => "-port", short => $p}
        ],
        handler =>
            fun (Map) ->
                case decent_sup:start_link() of
                    {ok, _Pid} ->
                        % Open the socket
                        Port = maps:get(port, Map, decent_server:default_port()),
                        decent_server:open_socket(Port),
                        io:format("listening on port ~b~n", [Port]),
                        % Keep the shell process running
                        timer:sleep(infinity);
                    {error, Reason} ->
                        io:format("failed to start server: ~p~n", [Reason])
                end            
            end
    }.