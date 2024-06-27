-module(decent_crypto).

-export(
    [
        generate_ecdh_key_pair/0,
        generate_key_pair/0,
        encrypt/2,
        decrypt/4,
        sign/2,
        verify/3,
        hash/1,
        compute_shared_key/2
    ]
).

-define(AEAD_CIPHER, chacha20_poly1305).
-define(ECC_CURVE, x25519).
-define(DIGEST_TYPE, sha256).
-define(SIGN_ALG, eddsa).
-define(ED_CURVE, ed25519).

-spec generate_ecdh_key_pair() -> {crypto:ecdh_private(), crypto:ecdh_public()}.
generate_ecdh_key_pair() -> crypto:generate_key(ecdh, ?ECC_CURVE).

-spec generate_key_pair() -> {crypto:eddsa_private(), crypto:eddsa_public()}.
generate_key_pair() -> crypto:generate_key(?SIGN_ALG, ?ED_CURVE).

-spec encrypt(binary(), binary()) -> binary().
encrypt(Data, Key) ->
    Nonce = crypto:strong_rand_bytes(12),
    {Enc, Tag} =
        crypto:crypto_one_time_aead(?AEAD_CIPHER, Key, Nonce, Data, [], true),
    {Nonce, Enc, Tag}.


-spec decrypt(binary(), binary(), binary(), binary()) -> binary().
decrypt(Enc, Tag, Key, Nonce) ->
    crypto:crypto_one_time_aead(?AEAD_CIPHER, Key, Nonce, Enc, [], Tag, false).

-spec sign(iodata(), crypto:eddsa_private()) -> binary().
sign(Digest, PrivKey) ->
    crypto:sign(?SIGN_ALG, none, {digest, Digest}, [PrivKey, ?ED_CURVE]).

-spec verify(iodata(), binary(), crypto:eddsa_public()) -> boolean().
verify(Digest, Signature, PubKey) ->
    crypto:verify(
        ?SIGN_ALG,
        none,
        {digest, Digest},
        Signature,
        [PubKey, ?ED_CURVE]
    ).

-spec hash(iodata()) -> binary().
hash(Data) -> crypto:hash(?DIGEST_TYPE, Data).

-spec compute_shared_key(crypto:ecdh_public(), crypto:ecdh_private()) ->
    binary().
compute_shared_key(OtherPub, MyPriv) ->
    crypto:compute_key(ecdh, OtherPub, MyPriv, ?ECC_CURVE).
