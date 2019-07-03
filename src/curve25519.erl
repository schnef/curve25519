-module(curve25519).

-export([make_private/0, make_private/1, make_public/1, 
	 key_pair/0, key_pair/1,
	 make_shared/2, sign/2, sign/3, verify/3]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-on_load(init/0).

priv_dir() ->
    case code:priv_dir(curve25519) of
	{error, bad_name} ->
	    "./priv";
	D ->
	    D
    end.


%% @doc
%% Load the curve25519_donna_nif.
%% @return ok 
%% @end
-spec init() -> ok.
init() ->
    ok = erlang:load_nif(priv_dir() ++ "/curve25519_drv", 0).

%% @doc 
%% Make a secret into a private key.
%% @return Private_key a 32-byte Curve25519 private key
%% @end
-spec make_private() -> Private_key :: iodata().
make_private() ->
    make_private(crypto:strong_rand_bytes(32)).

%% @doc 
%% Make a secret into a private key.
%% @param Secret a 32-byte long binary or io_list.
%% @return Private_key a 32-byte Curve25519 private key
%% @end
-spec make_private(Secret :: iodata()) -> Private_key :: iodata().
make_private(_Secret) ->
    exit(nif_library_not_loaded).
    
%% @doc
%% Generate the 32-byte Curve25519 public key
%% @param Private_key a 32-byte Curve25519 private key
%% @return Public_key the 32-byte Curve25519 public key
%% @end
-spec make_public(Private_key :: iodata()) -> Public_key :: iodata().
make_public(_Private_key) ->
    exit(nif_library_not_loaded).
    
%% @doc
%% Given someone else's Curve25519 public key, generate a 32-byte shared secret.
%% @param Public_key their 32-byte Curve25519 public key
%% @param Private_key my 32-byte Curve25519 private key 
%% @return Shared_key 32-byte Curve25519 shared key
%% @end
-spec make_shared(Public_key :: iodata(), Private_key :: iodata()) -> Shared_key :: iodata().
make_shared(_Public_key, _Private_key) ->
    exit(nif_library_not_loaded).

%% @doc
%% Generate a curve25519 keypair. Uses crypto:strong_rand_bytes as a secret.
%% @return {Private_key, Public_key}
%% @end
-spec key_pair() -> {Private_key :: iodata(), Public_key :: iodata()}.
key_pair() ->
    key_pair(crypto:strong_rand_bytes(32)).

%% @doc
%% Given a randomly generated secret of 32 bytes, generate a private and public key pair.
%% @param Seed of 32 bytes. Should be truely random.
%% @return {Private_key, Public_key}
%% @end
-spec key_pair(Secret :: iodata()) -> {Private_key :: iodata(), Public_key :: iodata()}.
key_pair(_Secret) ->
    exit(nif_library_not_loaded).

%% @doc
%% Sign a message with a curve25519 private key.
%% @param Private_key my 32-byte Curve25519 private key 
%% @param Message Payload to sign. Should not be larger then 256 bytes
%% @return Shared_key 32-byte Curve25519 shared key
%% @end
-spec sign(Private_key :: iodata(), Message :: iodata()) -> Sig :: iodata().
sign(Private_key, Message) ->
    sign(Private_key, Message, crypto:strong_rand_bytes(64)).

%% @doc
%% Sign a message with a curve25519 private key.
%% @param Private_key my 32-byte Curve25519 private key 
%% @param Message Payload to sign. Should not be larger then 256 bytes
%% @param Random a 64 bytes random binary.
%% @return Signature
%% @end
-spec sign(Private_key :: iodata(), Message :: iodata(), Random :: iodata()) -> Sig :: iodata().
sign(_Private_key, _Message, _Random) ->
    exit(nif_library_not_loaded).

%% @doc
%% Verify that message and signature match
%% @param Public_key their 32-byte Curve25519 public key 
%% @param Message Payload to verify. Should not be larger then 256 bytes
%% @param Signature their signature.
%% @return true if matches, otherwise false
%% @end
-spec verify(Public_key :: iodata(), Message :: iodata(), Signature :: iodata()) -> true | false.
verify(_Public_key, _Message, _Signature) ->
    exit(nif_library_not_loaded).



-ifdef(TEST).

curve25519_test() ->
    Secret_A = <<"01234567890123456789012345678901">>,
    Private_key_A = make_private(Secret_A),
    Public_key_A = make_public(Private_key_A),

    Secret_B = <<"abcdefghijklmnopqrstuvwxyz012345">>,
    Private_key_B = make_private(Secret_B),
    Public_key_B = make_public(Private_key_B),
    
    Shared_key_A = make_shared(Public_key_B, Private_key_A),
    Shared_key_B = make_shared(Public_key_A, Private_key_B),
    
    ?assert(Shared_key_A == Shared_key_B).
 

curve25519_RFC_8031_test() ->
    I = ["75","1f","b4","30","86","55","b4","76","b6","78","9b","73","25","f9","ea","8c",
	 "dd","d1","6a","58","53","3f","f6","d9","e6","00","09","46","4a","5f","9d","94"],
    R = ["0a","54","64","52","53","29","0d","60","dd","ad","d0","e0","30","ba","cd","9e",
	 "55","01","ef","dc","22","07","55","a1","e9","78","f1","b8","39","a0","56","88"],
    S = ["c7","49","50","60","7a","12","32","7f","32","04","d9","4b","68","25","bf","b0",
	 "68","b7","f8","31","9a","9e","37","08","ed","3d","43","ce","81","30","c9","50"],
    Random_i = list_to_binary([list_to_integer(X, 16) || X <- I]),
    Random_r = list_to_binary([list_to_integer(X, 16) || X <- R]),
    Shared_secret = list_to_binary([list_to_integer(X, 16) || X <- S]),

    D_i = make_private(Random_i),
    Pub_i = make_public(D_i),
    D_r = make_private(Random_r),
    Pub_r = make_public(D_r),
    Shared_secret_i = make_shared(Pub_r, D_i),
    Shared_secret_r = make_shared(Pub_i, D_r),
    
    ?assert(Shared_secret_i =:= Shared_secret andalso Shared_secret_r =:= Shared_secret).

-endif.
