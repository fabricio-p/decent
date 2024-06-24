-record(handshake_req, {key :: binary()}).
-record(handshake_ack, {key :: binary()}).
-record(handshake_ack_secret, {key :: binary(), secret :: binary()}).
-record(encrypted_msg, {nonce :: binary(), tag :: binary(), data :: binary()}).

