-record(handshake_req, {key :: binary()}).
-record(handshake_ack, {key :: binary()}).
-record(encrypted, {nonce :: binary(), tag :: binary(), data :: binary()}).
-record(handshake_ack_secret, {key :: binary(), secret :: #encrypted{}}).

