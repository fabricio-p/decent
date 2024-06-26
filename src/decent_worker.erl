-module(decent_worker).

-behaviour(gen_server).

-include("decent_protocol.hrl").

-export([start_link/1]).
-export([try_connect/1, message/2, send_message/2]).
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

%% INTERFACE -------------------------------------------------------------------

-spec start_link({inet:ip_address(), inet:port_number()}) ->
    gen_server:start_ret().
start_link(InitialState) -> gen_server:start_link(?MODULE, InitialState, []).

try_connect(Pid) -> gen_server:cast(Pid, try_connect).

message(Pid, Data) -> gen_server:cast(Pid, {message, Data}).

send_message(Pid, Data) -> gen_server:cast(Pid, {send_message, Data}).

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
             | {shared, binary()}.
-type state() :: #state{}.

-spec init({inet:ip_address(), inet:port_number()}) -> {ok, state()}.
init({Ip, Port, Key}) -> {ok, #state{ip = Ip, port = Port, key = Key}}.

handle_call(_Data, _From, State) -> {reply, ok, State}.

% We assume try_connect is called only one time before anything
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

handle_cast({message, Packet}, State) ->
    NewState =
        case decent_protocol:deserialize_packet(Packet) of
            {ok, Data} -> process_packet(Data, State)
        end,
    {noreply, NewState};

handle_cast(
    {send_message, SerializedPacket},
    #state{ip = Ip, port = Port} = State
) ->
    decent_server:send_data(SerializedPacket, Ip, Port),
    {noreply, State}.


terminate(_Reason, _State) -> nil.

%% Internal private functions --------------------------------------------------

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
    decent_server:assign_secret(Shared),
    Packet = #handshake_ack{key = MyPub},
    Data = decent_protocol:serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    State#state{key = {shared, Shared}};

process_packet(
    #handshake_req{key = OtherPub} = ReceivedPacket,
    #state{ip = Ip, port = Port, key = {shared, Secret}} = State
) ->
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, process_packet, 2},
            packet => ReceivedPacket,
            key => {shared, Secret}
        }
    ),
    {MyPub, MyPriv} = decent_crypto:generate_key_pair(),
    % NOTE: Shared here and the {shared, Secret} might cause confusion
    Shared = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    {Nonce, Enc, Tag} = decent_crypto:encrypt_data(Secret, Shared),
    Packet =
        #handshake_ack_secret{
            key = MyPub,
            secret = #encrypted{nonce = Nonce, tag = Tag, data = Enc}
        },
    Data = decent_protocol:serialize_packet(Packet),
    decent_server:send_data(Data, Ip, Port),
    State;

process_packet(
    #handshake_ack{key = OtherPub},
    #state{ip = Ip, port = Port, key = {pair, _MyPub, MyPriv}} = State
) ->
    Secret = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    logger:debug(
        #{
            from => {Ip, Port},
            in => {decent_worker, process_packet, 2},
            secret => Secret
        }
    ),
    decent_server:assign_secret(Secret),
    State#state{key = {shared, Secret}};

process_packet(
    #handshake_ack_secret{
        key = OtherPub,
        secret = #encrypted{nonce = Nonce, tag = Tag, data = Enc}
    },
    #state{ip = Ip, port = Port, key = {pair, _MyPub, MyPriv}} = State
) ->
    logger:notice("Request for ~p acknowledged with secret", [{Ip, Port}]),
    Shared = decent_crypto:compute_shared_key(OtherPub, MyPriv),
    % TODO: handle when this is `error`
    Secret = decent_crypto:decrypt_data(Enc, Tag, Shared, Nonce),
    decent_server:assign_secret(Secret),
    State#state{key = {shared, Secret}};

process_packet(
    #encrypted{nonce = Nonce, tag = Tag, data = Enc},
    #state{key = {shared, Key}} = State
) ->
    % TODO: handle when this is `error`
    Serialized = decent_crypto:decrypt_data(Enc, Tag, Key, Nonce),
    case decent_protocol:deserialize_packet(Serialized) of
        {ok, #text_packet{content = Content}} -> process_text(Content, State)
    end.


process_text(Data, #state{ip = Ip, port = Port} = State) ->
    io:format("\r~p: ~s~n>> ", [{Ip, Port}, Data]),
    State.
