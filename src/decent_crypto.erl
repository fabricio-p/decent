-module(decent_crypto).

-export(
    [generate_key_pair/0, encrypt_data/2, decrypt_data/4, compute_shared_key/2]
).

-define(AEAD_CIPHER, chacha20_poly1305).
-define(ECC_CURVE, x25519).

-spec generate_key_pair() -> {crypto:ecdh_private(), crypto:ecdh_public()}.
generate_key_pair() -> crypto:generate_key(ecdh, ?ECC_CURVE).

-spec encrypt_data(binary(), binary()) -> binary().
encrypt_data(Data, Key) ->
    Nonce = crypto:strong_rand_bytes(12),
    {Enc, Tag} =
        crypto:crypto_one_time_aead(?AEAD_CIPHER, Key, Nonce, Data, [], true),
    {Nonce, Enc, Tag}.


-spec decrypt_data(binary(), binary(), binary(), binary()) -> binary().
decrypt_data(Enc, Tag, Key, Nonce) ->
    crypto:crypto_one_time_aead(?AEAD_CIPHER, Key, Nonce, Enc, [], Tag, false).

-spec compute_shared_key(crypto:ecdh_public(), crypto:ecdh_private()) ->
    binary().
compute_shared_key(OtherPub, MyPriv) ->
    crypto:compute_key(ecdh, OtherPub, MyPriv, ?ECC_CURVE).
