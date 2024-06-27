-module(decent_protocol).

-include("decent_protocol.hrl").

-type handshake_req() :: #handshake_req{}.
-type handshake_ack() :: #handshake_ack{}.
-type handshake_ack_roomkey() :: #handshake_ack_roomkey{}.
-type encrypted() :: #encrypted{}.
-type raw_packet() :: handshake_req()
                    | handshake_ack()
                    | handshake_ack_roomkey()
                    | encrypted().

-export([serialize_packet/1, deserialize_packet/1]).

-ifdef('EUNIT').

-compile(nowarn_export_all).
-compile(export_all).

-endif.

-export_type([handshake_req/0, handshake_ack/0, encrypted/0]).

-spec serialize_packet(raw_packet()) -> binary().

serialize_packet(#signed{pubkey = PubKey, signature = Signature, data = #encrypted{nonce = Nonce, tag = Tag, data = Data}}) ->
    <<0, PubKey/binary, Signature/binary, Nonce/binary, Tag/binary, Data/binary>>;

serialize_packet(#handshake_req{key = Key}) -> <<10, Key/binary>>;
serialize_packet(#handshake_ack{key = Key}) -> <<11, Key/binary>>;

serialize_packet(
    #handshake_ack_roomkey{
        key = Key,
        roomkey = #encrypted{nonce = Nonce, tag = Tag, data = RoomKey}
    }
) ->
    <<12, Key/binary, Nonce/binary, Tag/binary, RoomKey/binary>>;

serialize_packet(#message_packet{nick = Nick, content = Content}) ->
    NickBinary = serialize_varbinary(<<Nick/binary>>),
    <<13, NickBinary/binary, Content/binary>>;

serialize_packet(#peers_packet{peers = Peers}) ->
    {PeerCount, SerializedPeers} = serialize_peers(Peers),
    <<14, PeerCount:32/big, SerializedPeers/binary>>.

-spec deserialize_packet(binary()) ->
    {ok, raw_packet()} | {error, Reason} when Reason :: invalid.

deserialize_packet(<<0, PubKey:32/binary, Signature:64/binary, Nonce:12/binary, Tag:16/binary, Data/binary>>) ->
    {ok, #signed{pubkey = PubKey, signature = Signature, data = #encrypted{nonce = Nonce, tag = Tag, data = Data}}};

deserialize_packet(<<10, Data/binary>>) -> {ok, #handshake_req{key = Data}};
deserialize_packet(<<11, Data/binary>>) -> {ok, #handshake_ack{key = Data}};

deserialize_packet(
    <<12, Key:32/binary, Nonce:12/binary, Tag:16/binary, RoomKey/binary>>
) ->
    {
        ok,
        #handshake_ack_roomkey{
            key = Key,
            roomkey = #encrypted{nonce = Nonce, tag = Tag, data = RoomKey}
        }
    };

deserialize_packet(<<13, NickAndContent/binary>>) ->
    {Nick, Content} = deserialize_varbinary(NickAndContent),
    {ok, #message_packet{nick = Nick, content = Content}};

deserialize_packet(<<14, PeerCount:32/big, SerializedPeers/binary>>) ->
    case deserialize_peers(PeerCount, SerializedPeers) of
        {ok, Peers} -> {ok, #peers_packet{peers = Peers}};
        Error -> Error
    end;

deserialize_packet(_Data) -> {error, invalid}.

serialize_peers(Peers) -> serialize_peers(Peers, 0, <<>>).

serialize_peers([], Count, Serialized) -> {Count, Serialized};

serialize_peers([Peer | Rest], Count, Serialized) ->
    SerializedPeer = serialize_peer(Peer),
    serialize_peers(
        Rest,
        Count + 1,
        <<Serialized/binary, SerializedPeer/binary>>
    ).


% NOTE: For now we only do IPv4
serialize_peer({{Ip0, Ip1, Ip2, Ip3}, Port}) ->
    <<Ip0, Ip1, Ip2, Ip3, Port:16/big>>.

deserialize_peers(PeerCount, SerializedPeers) ->
    deserialize_peers(PeerCount, SerializedPeers, []).

deserialize_peers(_PeerCount, <<>>, Peers) -> {ok, Peers};

deserialize_peers(PeerCount, SerializedPeers, Peers) ->
    case deserialize_peer(SerializedPeers) of
        {ok, Peer, Rest} ->
            deserialize_peers(PeerCount - 1, Rest, [Peer | Peers]);

        Error -> Error
    end.


deserialize_peer(<<Ip0, Ip1, Ip2, Ip3, Port:16/big, Rest/binary>>) ->
    Ip = {Ip0, Ip1, Ip2, Ip3},
    Peer = {Ip, Port},
    {ok, Peer, Rest};

deserialize_peer(_Data) ->
    % NOTE: The errors could be more descriptive
    {error, invalid_peer}.


serialize_varbinary(Data) ->
    Size = byte_size(Data),
    <<Size:32/big, Data/binary>>.


deserialize_varbinary(<<Size:32/big, Data/binary>>) ->
    <<TargetData:Size/binary, Rest/binary>> = Data,
    {TargetData, Rest}.
