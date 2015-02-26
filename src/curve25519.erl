-module(curve25519).

-export([make_private/1, make_public/1, make_shared/2]).

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
%% @param Private_key my 32-byte Curve25519 private key 
%% @param Public_key their 32-byte Curve25519 public key
%% @return Shared_key 32-byte Curve25519 shared key
%% @end
-spec make_shared(Private_key :: iodata(), Public_key :: iodata()) -> Shared_key :: iodata().
make_shared(_Private_key, _Public_key) ->
    exit(nif_library_not_loaded).

-ifdef(TEST).

curve25519_test() ->
    Private_key_A = make_private(<<"01234567890123456789012345678901">>),
    Public_key_A = make_public(Private_key_A),
   
    Private_key_B = make_private(<<"abcdefghijklmnopqrstuvwxyz012345">>),
    Public_key_B = make_public(Private_key_B),
    
    Shared_key_A = make_shared(Private_key_A, Public_key_B),
    Shared_key_B = make_shared(Private_key_B, Public_key_A),
    
    ?assert(Shared_key_A == Shared_key_B).
 
-endif.
