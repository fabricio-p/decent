-module(decent_protocol_tests).

-compile(nowarn_export_all).
-compile(export_all).

-include_lib("eunit/include/eunit.hrl").
-include("decent_protocol.hrl").

serde_peers_test() ->
    Peers = [{{127, 0, 0, 1}, 2000}, {{192, 168, 12, 223}, 4011}],
    Packet = #peers_packet{peers = Peers},
    Serialized = decent_protocol:serialize_packet(Packet),
    io:format("Packet: ~p~nSerialized: ~p~n", [Packet, Serialized]),
    ExpectedPacket = #peers_packet{peers = lists:reverse(Peers)},
     ?assertEqual({ok, ExpectedPacket},
                  decent_protocol:deserialize_packet(Serialized)).