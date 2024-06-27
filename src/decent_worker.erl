-module(decent_worker).

-behaviour(gen_server).

-include("decent_protocol.hrl").

-export([start_link/1]).
-export([try_connect/1, handle_packet/2]).
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

%% INTERFACE -------------------------------------------------------------------

-spec start_link({inet:ip_address(), inet:port_number()}) ->
    gen_server:start_ret().
start_link(InitialState) -> gen_server:start_link(?MODULE, InitialState, []).

try_connect(Pid) -> gen_server:cast(Pid, try_connect).

handle_packet(Pid, Data) -> gen_server:cast(Pid, {handle_packet, Data}).

%% gen_server internals --------------------------------------------------------

-record(
    state,
    {
        ip :: inet:ip_address(),
        port :: inet:port_number(),
        key = nil :: nil | key()
    }
).

-type key() :: {pair, crypto:ecdh_public(), crypto:ecdh_private()}
             | {roomkey, binary()}.
-type state() :: #state{}.

-spec init({inet:ip_address(), inet:port_number()}) -> {ok, state()}.
init({Ip, Port, Key}) -> {ok, #state{ip = Ip, port = Port, key = Key}}.

%% We're not handling any calls

handle_call(_Data, _From, State) -> {reply, ok, State}.

%% We assume try_connect is called only one time before anything

handle_cast(try_connect, #state{ip = Ip, port = Port} = State) ->
    {Pub, Priv} = decent_crypto:generate_key_pair(),
    Packet = #handshake_req{key = Pub},
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, process_packet, 2},
            packet => Packet
        }
    ),
    Data = decent_protocol:serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    {noreply, State#state{key = {pair, Pub, Priv}}};

%% We received a packet, process it
handle_cast({handle_packet, Packet}, State) ->
    NewState =
        case decent_protocol:deserialize_packet(Packet) of
            {ok, Data} -> process_packet(Data, State)
        end,
    {noreply, NewState}.

%% Terminates the worker

terminate(_Reason, _State) -> nil.

%% We're creating the room key since one doesn't exist yet

process_packet(
    #handshake_req{key = OtherPub} = ReceivedPacket,
    #state{ip = Ip, port = Port, key = nil} = State
) ->
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, process_packet, 2},
            packet => ReceivedPacket,
            key => nil
        }
    ),
    {MyPub, MyPriv} = decent_crypto:generate_key_pair(),
    Shared = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    decent_server:assign_room_key(Shared),
    Packet = #handshake_ack{key = MyPub},
    Data = decent_protocol:serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    State#state{key = {roomkey, Shared}};

%% We already have a room key so we encrypt it with the shared key and send it
process_packet(
    #handshake_req{key = OtherPub} = ReceivedPacket,
    #state{ip = Ip, port = Port, key = {roomkey, RoomKey}} = State
) ->
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, process_packet, 2},
            packet => ReceivedPacket,
            key => {roomkey, RoomKey}
        }
    ),
    {MyPub, MyPriv} = decent_crypto:generate_key_pair(),
    Shared = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    {Nonce, Enc, Tag} = decent_crypto:encrypt_data(RoomKey, Shared),
    Packet =
        #handshake_ack_roomkey{
            key = MyPub,
            roomkey = #encrypted{nonce = Nonce, tag = Tag, data = Enc}
        },
    Data = decent_protocol:serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    State;

%% Acknowledged, the shared key will become the room key
process_packet(
    #handshake_ack{key = OtherPub},
    #state{ip = Ip, port = Port, key = {pair, _MyPub, MyPriv}} = State
) ->
    RoomKey = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, process_packet, 2},
            roomkey => RoomKey
        }
    ),
    decent_server:assign_room_key(RoomKey),
    State#state{key = {roomkey, RoomKey}};

%% Acknowledged, we received an encrypted room key
process_packet(
    #handshake_ack_roomkey{
        key = OtherPub,
        roomkey = #encrypted{nonce = Nonce, tag = Tag, data = Enc}
    },
    #state{ip = Ip, port = Port, key = {pair, _MyPub, MyPriv}} = State
) ->
    logger:notice("Request for ~p acknowledged with room key", [{Ip, Port}]),
    Shared = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    % TODO: handle when this is `error`
    RoomKey = decent_crypto:decrypt_data(Enc, Tag, Shared, Nonce),
    decent_server:assign_room_key(RoomKey),
    State#state{key = {roomkey, RoomKey}};

%% We received an encrypted message
process_packet(
    #encrypted{nonce = Nonce, tag = Tag, data = Enc},
    #state{key = {roomkey, Key}} = State
) ->
    % TODO: handle when this is `error`
    Serialized = decent_crypto:decrypt_data(Enc, Tag, Key, Nonce),
    case decent_protocol:deserialize_packet(Serialized) of
        {ok, #text_packet{content = Content}} -> process_text(Content, State)
    end.


process_text(Data, #state{ip = Ip, port = Port} = State) ->
    io:format("\r~p: ~s~n>> ", [{Ip, Port}, Data]),
    State.
