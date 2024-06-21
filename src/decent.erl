%%%-------------------------------------------------------------------
%% @doc we parse command line args here
%% @end
%%%-------------------------------------------------------------------

-module(decent).

-export([main/1]).
-include_lib("kernel/include/inet.hrl").

main(Args) ->
    argparse:run(Args, cli(), #{progname => decent}).

cli() -> #{
        arguments => [
            #{name => port, type => integer, long => "-port", short => $p},
            #{name => address}
        ],
        handler =>
            fun (Args) ->
                {DstIp, DstPort} = case maps:get(address, Args, none) of 
                    none -> io:format("no hostname supplied~n"), exit(no_hostname);
                    Address -> 
                        {Host, ParsedPort} = parse_address(Address),
                        case resolve_host(Host) of 
                            {ok, Ip} -> {Ip, ParsedPort};
                            {error, ResolveReason} -> io:format("failed to resolve ~s: ~p~n", [Address, ResolveReason]), exit(ResolveReason)
                        end
                end,
                case decent_sup:start_link() of
                    {ok, _Pid} ->
                        Port = maps:get(port, Args, decent_server:default_port()),
                        decent_server:open_socket(Port),
                        io:format("listening on port ~b~n", [Port]),
                        % keep the shell process running
                        input_loop(DstIp, DstPort);
                    {error, StartReason} ->
                        io:format("failed to start server: ~p~n", [StartReason])
                end
            end
    }.

input_loop(DstIp, DstPort) ->
    {ok, [Message]} = io:fread(">> ", "~s"),
    decent_server:send_data(DstIp, DstPort, Message),
    input_loop(DstIp, DstPort).

parse_address(Address) -> 
    case string:tokens(Address, ":") of
        [Host, Port] ->
            {Host, list_to_integer(Port)};
        [Host] -> 
            {Host, decent_server:default_port()};
        _ ->
            {error, invalid_format}
    end.

resolve_host(Host) ->
    case inet:gethostbyname(Host) of
        {ok, HostEnt} -> {ok, hd(HostEnt#hostent.h_addr_list)};
        {error, Reason} -> {error, Reason}
    end.
