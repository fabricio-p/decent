-module(decent_worker).

-behaviour(gen_server).

-export([start_link/1]).

-export([try_connect/1, message/2, send_message/2]).

-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

%% INTERFACE -------------------------------------------------------------------
-spec start_link({inet:ip_address(),
                  inet:port_number()}) -> gen_server:start_ret().
start_link(InitialState) ->
    gen_server:start_link(?MODULE, InitialState, []).

try_connect(Pid) ->
    gen_server:cast(Pid, try_connect).

message(Pid, Data) ->
    gen_server:cast(Pid, {message, Data}).

send_message(Pid, Data) ->
    gen_server:cast(Pid, {send_message, Data}).
%% gen_server internals --------------------------------------------------------

-define(ASYMETRIC_KEY_KIND, ecdh).
-define(ECDH_CURVE, x25519).

-record(state, {ip        :: inet:ip_address(),
                port      :: inet:port_number(),
                key = nil :: nil | key()}).

-record(handshake_req, {key :: binary()}).
-record(handshake_ack, {key :: binary()}).
-record(encrypted, {data :: binary()}).

-record(text_pack, {content :: binary()}).

-type key() :: {pair,
                crypto:ecdh_public(),
                crypto:ecdh_private()} |
                % NOTE: the key probably is some other more specific type
                {shared, binary()}.
-type state() :: #state{}.

-type handshake_req() :: #handshake_req{}.
-type handshake_ack() :: #handshake_ack{}.
-type encrypted() :: #encrypted{}.

-type text_pack() :: #text_pack{}.

-type raw_packet() :: handshake_req() | handshake_ack() | encrypted().
-type encryped_packet() :: text_pack().

-spec init({inet:ip_address(), inet:port_number()}) -> {ok, state()}.
init({Ip, Port}) ->
    {ok, #state{ip = Ip, port = Port}}.

handle_call(_Data, _From, State) ->
    {reply, ok, State}.

% We assume try_connect is called only one time before anything
handle_cast(try_connect, #state{ip = Ip, port = Port} = State) ->
    logger:notice("Trying to connect", []),
    Pub = <<"">>,
    Priv = <<"">>,
    Key = {pair, Pub, Priv},
    Packet = #handshake_req{key = Pub},
    Data = serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    {noreply, State#state{key = Key}};

handle_cast({message, Data}, #state{key = nil} = State) ->
    NewState =
        case deserialize_packet(Data) of
            #handshake_req{key = Key} ->
                process_request(Key, State);
            #text_pack{content = Content} ->
                process_text(Content, State)
        end,
    {noreply, NewState};

handle_cast({message, Data}, #state{key = {pair, _Pub, _Priv}} = State) ->
    NewState =
        case deserialize_packet(Data) of
            #handshake_ack{key = Key} ->
                process_acknowledgement(Key, State)
            % let it crash for now
        end,
    {noreply, NewState};

handle_cast(
  {message, Data},
  #state{key = {shared, Key}, ip = Ip, port = Port} = State
 ) ->
    #encrypted{data = EncryptedInnerPacket} = deserialize_packet(Data),
    SerializedInnerPacket = decrypt_data(EncryptedInnerPacket, Key),
    #text_pack{content = Content} = deserialize_packet(SerializedInnerPacket),
    io:format("~p: ~p~n", [{Ip, Port}, Content]),
    {noreply, State};

handle_cast(
  {send_message, Data},
  #state{key = {shared, Key}, ip = Ip, port = Port} = State
 ) ->
    InnerPacket = #text_pack{content = Data},
    SerializedInnerPacket = serialize_packet(InnerPacket),
    EncryptedInnerPacket = encrypt_data(SerializedInnerPacket, Key),
    Packet = #encrypted{data = EncryptedInnerPacket},
    SerializedPacket = serialize_packet(Packet),
    decent_server:send_data(SerializedPacket, Ip, Port),
    {noreply, State}.

terminate(_Reason, _State) ->
    nil.

%% Internal private functions --------------------------------------------------
process_request(OtherPub, #state{ip = Ip, port = Port} = State) ->
    logger:notice("Processing request from ~p", [{Ip, Port}]),
    Pub = <<"">>,
    Priv = <<"">>,
    Shared = compute_shared_key(Priv, OtherPub),
    Key = {shared, Shared},
    Packet = #handshake_ack{key = Pub},
    Data = serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    State#state{key = Key}.

process_acknowledgement(OtherPub, #state{key = {pair, _Pub, Priv}} = State) ->
    logger:notice("Request for ~p acknowledged",
                 [{State#state.ip, State#state.port}]),
    Shared = compute_shared_key(Priv, OtherPub),
    Key = {shared, Shared},
    State#state{key = Key}.

process_text(Data, #state{ip = Ip, port = Port, key = {shared, Key}} = State) ->
    Content = decrypt_data(Data, Key),
    io:format("~p: ~p~n", [{Ip, Port}, Content]),
    State.

% TODO: To encrypt and serialize with protobuf
% NOTE: The binary()/whatever types should should be aliased to more specific
%       names.
-spec encrypt_data(binary(), binary()) -> binary().
encrypt_data(Data, _Key) ->
    Data.

-spec serialize_packet(raw_packet() | encryped_packet()) -> binary().
serialize_packet(Packet) ->
    term_to_binary(Packet).

-spec decrypt_data(binary(), binary()) -> binary().
decrypt_data(Data, _Key) ->
    Data.

-spec deserialize_packet(binary()) -> raw_packet() | encryped_packet().
deserialize_packet(Data) ->
    binary_to_term(Data).

-spec compute_shared_key(binary(), binary()) -> binary().
compute_shared_key(_MyPriv, _OtherPub) ->
    <<"">>.