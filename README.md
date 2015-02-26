# curve25519
curve25519 as a Erlang NIF

## Install

Get the repo from github and build with rebar.

```
$ cd curve25519/
$ rebar clean compile eunit doc
```

## Usage

```
show_me_how() ->
    Secret_A = <<"01234567890123456789012345678901">>,
    Private_key_A = curve25519:make_private(Secret_A),
    Public_key_A = curve25519:make_public(Private_key_A),

    Secret_B = <<"abcdefghijklmnopqrstuvwxyz012345">>,
    Private_key_B = curve25519:make_private(Secret_B),
    Public_key_B = curve25519:make_public(Private_key_B),

    Shared_key_A = curve25519:make_shared(Private_key_A, Public_key_B),
    Shared_key_B = curve25519:make_shared(Private_key_B, Public_key_A),
    
    Shared_key_A == Shared_key_B.
```
