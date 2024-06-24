-module(decent_crypto).

-define(AEAD_CIPHER, chacha20_poly1305).
-export([encrypt_data/2, decrypt_data/4]).

-spec encrypt_data(binary(), binary()) -> binary().
encrypt_data(Data, Key) ->
    Nonce = crypto:strong_rand_bytes(12),
    {Enc, Tag} = crypto:crypto_one_time_aead(?AEAD_CIPHER, Key, Nonce, Data, [], true),
    {Nonce, Enc, Tag}.

-spec decrypt_data(binary(), binary(), binary(), binary()) -> binary().
decrypt_data(Enc, Tag, Key, Nonce) ->
    crypto:crypto_one_time_aead(?AEAD_CIPHER, Key, Nonce, Enc, [], Tag, false).
