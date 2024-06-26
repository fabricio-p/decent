-module(decent_protocol).

-include("decent_protocol.hrl").

-type handshake_req() :: #handshake_req{}.
-type handshake_ack() :: #handshake_ack{}.
-type handshake_ack_secret() :: #handshake_ack_secret{}.
-type encrypted() :: #encrypted{}.
-type raw_packet() :: handshake_req()
                    | handshake_ack()
                    | handshake_ack_secret()
                    | encrypted().

-export([serialize_packet/1, deserialize_packet/1]).

-ifdef('EUNIT').

-compile(nowarn_export_all).
-compile(export_all).

-endif.

-export_type([handshake_req/0, handshake_ack/0, encrypted/0]).

-spec serialize_packet(raw_packet()) -> binary().
serialize_packet(#handshake_req{key = Key}) -> <<0, Key/binary>>;
serialize_packet(#handshake_ack{key = Key}) -> <<1, Key/binary>>;

serialize_packet(
    #handshake_ack_secret{
        key = Key,
        secret = #encrypted{nonce = Nonce, tag = Tag, data = Secret}
    }
) ->
    <<2, Key/binary, Nonce/binary, Tag/binary, Secret/binary>>;

serialize_packet(#encrypted{nonce = Nonce, tag = Tag, data = Data}) ->
    <<3, Nonce/binary, Tag/binary, Data/binary>>;

serialize_packet(#text_packet{content = Content}) -> <<4, Content/binary>>;

serialize_packet(#peers_packet{peers = Peers}) ->
    {PeerCount, SerializedPeers} = serialize_peers(Peers),
    <<5, PeerCount:32/big, SerializedPeers/binary>>.


-spec deserialize_packet(binary()) ->
    {ok, raw_packet()} | {error, Reason} when Reason :: invalid.
deserialize_packet(<<0, Data/binary>>) -> {ok, #handshake_req{key = Data}};
deserialize_packet(<<1, Data/binary>>) -> {ok, #handshake_ack{key = Data}};

deserialize_packet(
    <<2, Key:32/binary, Nonce:12/binary, Tag:16/binary, Secret/binary>>
) ->
    {
        ok,
        #handshake_ack_secret{
            key = Key,
            secret = #encrypted{nonce = Nonce, tag = Tag, data = Secret}
        }
    };

deserialize_packet(<<3, Nonce:12/binary, Tag:16/binary, Data/binary>>) ->
    {ok, #encrypted{nonce = Nonce, tag = Tag, data = Data}};

deserialize_packet(<<4, Content/binary>>) ->
    {ok, #text_packet{content = Content}};

deserialize_packet(<<5, PeerCount:32/big, SerializedPeers/binary>>) ->
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
