%%%-------------------------------------------------------------------
%% @doc the genserver that handles the messaging etc.
%% @end
%%%-------------------------------------------------------------------

-module(decent_server).

-behaviour(gen_server).

-export([start_link/0]).

-export([default_port/0, open_socket/1, close_socket/0, send_data/1, connect_to/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/1]).

-record(state, {contacts = [], port = 0, socket = nil}).
-define(PORT, 16#fab).

%% INTERFACE ------------------------------------------

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

default_port() -> ?PORT.

open_socket(Port) ->
    gen_server:call(?MODULE, {open_socket, Port}).

close_socket() ->
    gen_server:call(?MODULE, close_socket).

send_data(Data) ->
    gen_server:cast(?MODULE, {send_data, Data}).

connect_to(Ip, Port) ->
    gen_server:cast(?MODULE, {connect_to, Ip, Port}).

%% ----------------------------------------------------

init(_Args) ->
    {ok, #state{}}.

handle_call({open_socket, Port}, _From, #state{socket = nil} = State) ->
    {ok, Socket} = gen_udp:open(Port, [binary, {active, true}]),
    {reply, ok, State#state{port = Port, socket = Socket}};

handle_call({open_socket, Port}, _From, #state{port = Port} = State) ->
    {reply, ok, State};

handle_call({open_socket, Port}, _From, #state{socket = OldSocket} = State) ->
    Result = gen_udp:close(OldSocket),
    {ok, Socket} = gen_udp:open(Port, [binary, {active, true}]),
    {reply, Result, State#state{port = Port, socket = Socket}};

handle_call(close_socket, _From, #state{socket = Socket} = State)
  when Socket =/= nil ->
    {noreply, gen_udp:close(Socket), State#state{port = 0, socket = nil}};

handle_call(close_socket, _From, #state{socket = nil} = State) ->
    {reply, ok, State}.

handle_cast(
  {send_data, Data},
  #state{contacts = Contacts, socket = Socket} = State
 ) ->
    lists:foreach(fun({ Ip, Port }) -> 
        spawn(fun() -> gen_udp:send(Socket, Ip, Port, Data) end)
    end, Contacts),
    
    {noreply, State};

handle_cast(
  {connect_to, Ip, Port},
  #state{ socket = Socket, contacts = Contacts } = State
 ) ->
    {Pub, _} = crypto:generate_key(ecdh, x25519),
    gen_udp:send(Socket, Ip, Port, Pub),
    {noreply, State#state { contacts = [{Ip, Port, Pub} | Contacts] } }.

handle_info(
  {udp, Socket, SrcIp, SrcPort, OtherPub},
  #state{ socket = Socket, contacts = Contacts } = State
) ->
    Secret = case lists:dropwhile(fun({Ip, Port, _}) -> Ip =/= SrcIp andalso Port =/= SrcPort end, Contacts) of % could use a refactor; this just finds the Pub with the right Ip and Port
        [] -> 
            {Pub, _} = crypto:generate_key(ecdh, x25519),
            gen_udp:send(Socket, SrcIp, SrcPort, Pub),
            crypto:compute_key(ecdh, Pub, OtherPub, x25519);
        [{_, _, Pub} | _] -> crypto:compute_key(ecdh, OtherPub, Pub, x25519)
    end,

    io:format("~p~n", [Secret]),
    %io:format("\r~s~n>> ", [Packet]),
    {noreply, State}.

terminate(#state{socket = Socket}) when Socket =/= nil ->
    gen_udp:close(Socket);

terminate(_State) -> nil.