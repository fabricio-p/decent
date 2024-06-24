-module(decent_protocol).

-include("decent_protocol.hrl").

-type handshake_req() :: #handshake_req{}.
-type handshake_ack() :: #handshake_ack{}.
-type handshake_ack_secret() :: #handshake_ack_secret{}.
-type encrypted() :: #encrypted{}.

-type raw_packet() :: handshake_req() | handshake_ack() | handshake_ack_secret() | encrypted().

-export([serialize_packet/1, deserialize_packet/1]).
-export_type([handshake_req/0, handshake_ack/0, encrypted/0]).

-spec serialize_packet(raw_packet()) -> binary().
serialize_packet(#handshake_req{key = Key}) ->
    <<0, Key/binary>>;
serialize_packet(#handshake_ack{key = Key}) ->
    <<1, Key/binary>>;
serialize_packet(#handshake_ack_secret{key = Key, secret = #encrypted{nonce = Nonce, tag = Tag, data = Secret}}) ->
    <<2, Key/binary, Nonce/binary, Tag/binary, Secret/binary>>;
serialize_packet(#encrypted{nonce = Nonce, tag = Tag, data = Data}) ->
    <<3, Nonce/binary, Tag/binary, Data/binary>>.

-spec deserialize_packet(binary()) -> {ok, raw_packet()} | {error, string()}.
deserialize_packet(<<0, Data/binary>>) -> {ok, #handshake_req{key = Data}};
deserialize_packet(<<1, Data/binary>>) -> {ok, #handshake_ack{key = Data}};
deserialize_packet(<<2, Key:32/binary, Nonce:12/binary, Tag:16/binary, Secret/binary>>) ->
    {ok, #handshake_ack_secret{key = Key, secret = #encrypted{nonce = Nonce, tag = Tag, data = Secret}}};
deserialize_packet(<<3, Nonce:12/binary, Tag:16/binary, Data/binary>>) -> 
    {ok, #encrypted{nonce = Nonce, tag = Tag, data = Data}};
deserialize_packet(_Data) -> {error, "malformed packet"}.
