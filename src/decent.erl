%%%-------------------------------------------------------------------
%% @doc we parse command line args here
%% @end
%%%-------------------------------------------------------------------

-module(decent).

-export([main/1]).

-include_lib("kernel/include/inet.hrl").

-record(state, {ip, port}).

main(Args) -> argparse:run(Args, cli(), #{progname => decent}).

cli() ->
    #{
        arguments
        =>
        [
            #{name => port, type => integer, long => "-port", short => $p},
            #{name => address, required => false}
        ],
        handler => fun handle_cli_args/1
    }.

handle_cli_args(Args) ->
    logger:set_primary_config(level, debug),
    case decent_app:start([], []) of
        {ok, _Pid} ->
            Port = maps:get(port, Args, decent_server:default_port()),
            decent_server:open_socket(Port),
            io:format("listening on port ~b~n", [Port]),
            State =
                case extract_parsed_address(Args) of
                    {ok, DstPort, DstIp} ->
                        decent_server:connect_to(DstIp, DstPort),
                        #state{ip = DstIp, port = DstPort};

                    _ -> #state{ip = nil, port = nil}
                end,
            % keep the shell process running
            loop(State);

        {error, Reason} -> io:format("failed to start app: ~p~n", [Reason])
    end.


loop(State) ->
    case io:get_line(">> ") of
        eof -> ok;

        Line ->
            Message = list_to_binary(string:trim(Line)),
            Length = string:length(Message),
            if
                Length =/= 0 -> decent_server:send_data(Message);
                true -> nil
            end,
            loop(State)
    end.


extract_parsed_address(Args) ->
    case maps:get(address, Args, nil) of
        nil -> {error, nil};

        AddrStr ->
            % this should probably be put in a case but I can't be bothered rn
            {ok, Port, Ip} = resolve_address(AddrStr),
            {ok, Port, Ip}
    end.


resolve_address(Address) ->
    % this should probably be put in a case but I can't be bothered rn
    {ok, Host, Port} = parse_address(Address),
    case resolve_host(Host) of
        {ok, Ip} -> {ok, Port, Ip};
        {error, ResolveReason} -> {error, ResolveReason}
    end.


parse_address(AddrStr) ->
    case string:tokens(AddrStr, ":") of
        [Host, PortStr] ->
            Port = list_to_integer(PortStr),
            {ok, Host, Port};

        [Host] ->
            Port = decent_server:default_port(),
            {ok, Host, Port};

        _ -> {error, invalid_address}
    end.


resolve_host(Host) ->
    case inet:gethostbyname(Host) of
        {ok, #hostent{h_addr_list = [Ip | _]}} -> {ok, Ip};
        {error, Reason} -> {error, Reason}
    end.
