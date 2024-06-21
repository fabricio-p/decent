%%%-------------------------------------------------------------------
%% @doc the genserver that handles the messaging etc.
%% @end
%%%-------------------------------------------------------------------

-module(decent_server).

-behaviour(gen_server).

-export([start_link/0]).

-export([default_port/0, open_socket/1, close_socket/0, send_data/3]).

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

send_data(Ip, Port, Data) ->
    gen_server:cast(?MODULE, {send_data, Ip, Port, Data}).

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
  {send_data, Ip, Port, Data},
  #state{socket = Socket} = State
 ) ->
    gen_udp:send(Socket, Ip, Port, Data),
    {noreply, State}.

handle_info(
  {udp, Socket, _Ip, _Port, Packet},
  #state{ socket = Socket } = State
) ->
    io:format("\r~s~n>> ", [Packet]),
    {noreply, State}.

terminate(#state{socket = Socket}) when Socket =/= nil ->
    gen_udp:close(Socket);

terminate(_State) -> nil.