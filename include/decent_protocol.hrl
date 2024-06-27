-record(encrypted, {nonce :: binary(), tag :: binary(), data :: binary()}).
-record(signed, {pubkey :: binary(), signature :: binary(), data :: #encrypted{}}).

-record(handshake_req, {key :: binary()}).
-record(handshake_ack, {key :: binary()}).
-record(handshake_ack_roomkey, {key :: binary(), roomkey :: #encrypted{}}).
-record(message_packet, {nick :: binary(), content :: binary()}).
-record(peers_packet, {peers :: [{inet:ip_address(), inet:port_number()}]}).
