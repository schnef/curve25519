# curve25519
curve25519-donna plus curve25519 signing and verifying as Erlang NIFs.

## Install
This is only tested on i386 and X86_64 Debian. It might very well work on other platforms as well.
Rebar is included with the repo. A C compiler should be available.
Get the repo from github and build with rebar.

```
$ cd curve25519/
$ ./rebar clean compile eunit doc
```

## Usage

```
show_me_how() ->
    Secret_A = <<"01234567890123456789012345678901">>,
    Private_key_A = make_private(Secret_A),
    Public_key_A = make_public(Private_key_A),

    Secret_B = <<"abcdefghijklmnopqrstuvwxyz012345">>,
    Private_key_B = make_private(Secret_B),
    Public_key_B = make_public(Private_key_B),
    
    Shared_key_A = make_shared(Public_key_B, Private_key_A),
    Shared_key_B = make_shared(Public_key_A, Private_key_B),
    
    Shared_key_A == Shared_key_B.
```
Now sign and verify:
```
$ erl -pa ../curve25519/ebin/
Erlang/OTP 17 [erts-6.3] [source] [64-bit] [smp:2:2] [async-threads:10] [kernel-poll:false]

Eshell V6.3  (abort with ^G)

9> l(curve25519).                  
{module,curve25519}
10> Csk = curve25519:make_private().
<<128,231,156,248,52,34,71,100,187,134,147,59,96,169,184,
  170,126,38,111,68,125,149,90,52,37,55,15,127,139,...>>
11> Cpk = curve25519:make_public(Csk).       
<<182,42,23,82,131,51,198,210,30,63,237,171,191,136,86,
  254,27,255,29,205,8,244,47,86,204,98,201,30,255,...>>
12> M = "Stupid message".              
"Stupid message"
13> Sig = curve25519:sign(Csk, M).     
<<214,205,244,91,4,136,155,160,13,146,224,109,111,21,109,
  38,28,118,159,101,149,208,249,74,121,153,174,150,178,...>>
14> curve25519:verify(Cpk, M, Sig).    
true
15> curve25519:verify(Cpk, "forged message", Sig).
false

```