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
    {Pub, Priv} = decent_crypto:generate_ecdh_key_pair(),
    Packet = #handshake_req{key = Pub},
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, try_process_private_packet, 2},
            packet => Packet
        }
    ),
    Data = decent_protocol:serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    {noreply, State#state{key = {pair, Pub, Priv}}};

%% We're in a room, be extra cautious with packets
%% Check if we've seen this packet before; if so, do nothing
handle_cast({handle_packet, Packet}, #state{key = {roomkey, _}} = State) ->
    case decent_server:seen_packet(Packet) of
        true -> {noreply, State};
        false -> handle_packet_impl(Packet, State)
    end;

%% We received a packet, process it
handle_cast({handle_packet, Packet}, State) ->
    handle_packet_impl(Packet, State).

%% Terminates the worker

terminate(_Reason, _State) -> nil.

handle_packet_impl(Packet, State) ->
    NewState =
        case decent_protocol:deserialize_packet(Packet) of
            {ok, Data} ->
                case try_process_private_packet(Data, State) of
                    next ->
                        decent_server:send_data(Packet),
                        process_public_packet(Data, State);

                    S -> S
                end
        end,
    {noreply, NewState}.

%% We're creating the room key since one doesn't exist yet

try_process_private_packet(
    #handshake_req{key = OtherPub} = ReceivedPacket,
    #state{ip = Ip, port = Port, key = nil} = State
) ->
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, try_process_private_packet, 2},
            packet => ReceivedPacket,
            key => nil
        }
    ),
    {MyPub, MyPriv} = decent_crypto:generate_ecdh_key_pair(),
    Shared = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    decent_server:assign_roomkey(Shared),
    Packet = #handshake_ack{key = MyPub},
    Data = decent_protocol:serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    State#state{key = {roomkey, Shared}};

%% We already have a room key so we encrypt it with the shared key and send it
try_process_private_packet(
    #handshake_req{key = OtherPub} = ReceivedPacket,
    #state{ip = Ip, port = Port, key = {roomkey, RoomKey}} = State
) ->
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, try_process_private_packet, 2},
            packet => ReceivedPacket,
            key => {roomkey, RoomKey}
        }
    ),
    {MyPub, MyPriv} = decent_crypto:generate_ecdh_key_pair(),
    Shared = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    {Nonce, Enc, Tag} = decent_crypto:encrypt(RoomKey, Shared),
    Packet =
        #handshake_ack_roomkey{
            key = MyPub,
            roomkey = #encrypted{nonce = Nonce, tag = Tag, data = Enc}
        },
    Data = decent_protocol:serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    State;

%% Acknowledged, the shared key will become the room key
try_process_private_packet(
    #handshake_ack{key = OtherPub},
    #state{ip = Ip, port = Port, key = {pair, _MyPub, MyPriv}} = State
) ->
    RoomKey = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, try_process_private_packet, 2},
            roomkey => RoomKey
        }
    ),
    decent_server:assign_roomkey(RoomKey),
    State#state{key = {roomkey, RoomKey}};

%% Acknowledged, we received an encrypted room key
try_process_private_packet(
    #handshake_ack_roomkey{
        key = OtherPub,
        roomkey = #encrypted{nonce = Nonce, tag = Tag, data = Enc}
    },
    #state{ip = Ip, port = Port, key = {pair, _MyPub, MyPriv}} = State
) ->
    logger:notice("Request for ~p acknowledged with room key", [{Ip, Port}]),
    Shared = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    % TODO: handle when this is `error`
    RoomKey = decent_crypto:decrypt(Enc, Tag, Shared, Nonce),
    decent_server:assign_roomkey(RoomKey),
    State#state{key = {roomkey, RoomKey}};

try_process_private_packet(_Packet, _State) -> next.

%% We received an encrypted message

process_public_packet(
    #signed {pubkey = OtherPub, signature = Signature, data = #encrypted{nonce = Nonce, tag = Tag, data = Enc}},
    #state{key = {roomkey, Key}} = State
) ->
    % TODO: handle when this is `error`
    Serialized = decent_crypto:decrypt(Enc, Tag, Key, Nonce),
    Digest = decent_crypto:hash(Serialized),
    true = decent_crypto:verify(Digest, Signature, OtherPub),
    case decent_protocol:deserialize_packet(Serialized) of
        {ok, #message_packet{nick = Nick, content = Content}} ->
            process_text(Nick, OtherPub, Content, State)
    end.


process_text(Nick, <<Checksum:32, _/binary>>, Content, State) ->
    ChecksumString = string:to_lower(io_lib:format("~7.16B", [Checksum bsr 4])),
    io:format("\r~s [~s]: ~s~n>> ", [Nick, ChecksumString, Content]),
    State.
