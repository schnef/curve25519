/*
 * Frans Schneider
 * Public domain.
 * 
 * Got inspiration from http://erlang.org/pipermail/erlang-questions/2011-April/057954.html
 */

#include <string.h>
#include "erl_nif.h"

#include "curve_sigs.h"

extern int curve25519_donna(unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);

static ERL_NIF_TERM make_private_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) 
{
  ERL_NIF_TERM ret;
  ErlNifBinary in;
  unsigned char* out;
  
  if (!enif_inspect_iolist_as_binary(env, argv[0], &in) || in.size != 32) {
    return enif_make_badarg(env);
  }
  out = enif_make_new_binary(env, 32, &ret);
  memcpy(out, in.data, 32);
  out[0] &= 248;
  out[31] &= 127;
  out[31] |= 64;
  return ret;
}

static ERL_NIF_TERM make_public_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) 
{
  ERL_NIF_TERM ret;
  ErlNifBinary private_key;
  unsigned char* public_key;
  const unsigned char basepoint[32] = {9};
  
  if (!enif_inspect_iolist_as_binary(env, argv[0], &private_key) || private_key.size != 32) {
    return enif_make_badarg(env);
  }
  public_key = enif_make_new_binary(env, 32, &ret);
  curve25519_donna(public_key, private_key.data, basepoint);
  return ret;
}

static ERL_NIF_TERM key_pair_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) 
{
  ERL_NIF_TERM private_key_term, public_key_term;
  ErlNifBinary seed;
  unsigned char* private_key;
  unsigned char* public_key;
  const unsigned char basepoint[32] = {9};
  
  private_key = enif_make_new_binary(env, 32, &private_key_term);
  public_key = enif_make_new_binary(env, 32, &public_key_term);
  
  if (!enif_inspect_iolist_as_binary(env, argv[0], &seed) || seed.size != 32) {
    return enif_make_badarg(env);
  }
  memcpy(private_key, seed.data, 32);
  private_key[0] &= 248;
  private_key[31] &= 127;
  private_key[31] |= 64;
  
  curve25519_donna(public_key, private_key, basepoint);

  return enif_make_tuple2(env, private_key_term, public_key_term);
}

static ERL_NIF_TERM make_shared_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) 
{
  ERL_NIF_TERM ret;
  ErlNifBinary their_public_key;
  ErlNifBinary my_private_key;
  unsigned char *shared_key;
  
  if (!enif_inspect_iolist_as_binary(env, argv[0], &their_public_key) || their_public_key.size != 32 ||
      !enif_inspect_iolist_as_binary(env, argv[1], &my_private_key) || my_private_key.size != 32) {
    return enif_make_badarg(env);
  }
  shared_key = enif_make_new_binary(env, 32, &ret);
  curve25519_donna(shared_key, my_private_key.data, their_public_key.data);
  return ret;
}

static ERL_NIF_TERM sign_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) 
{
  ERL_NIF_TERM ret;
  ErlNifBinary sk;
  ErlNifBinary msg;
  ErlNifBinary random;
  unsigned char *sig;

  if (!enif_inspect_iolist_as_binary(env, argv[0], &sk) || sk.size != 32 ||
      !enif_inspect_iolist_as_binary(env, argv[1], &msg) || msg.size == 0 || msg.size > 256 ||
      !enif_inspect_iolist_as_binary(env, argv[2], &random) || random.size != 64) {
    return enif_make_badarg(env);
  }
  sig = enif_make_new_binary(env, 64, &ret);

  curve25519_sign(sig, sk.data, msg.data, msg.size, random.data);

  return ret;
}

static ERL_NIF_TERM verify_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) 
{
  ErlNifBinary pk;
  ErlNifBinary msg;
  ErlNifBinary sig;

  if (!enif_inspect_iolist_as_binary(env, argv[0], &pk) || pk.size != 32 ||
      !enif_inspect_iolist_as_binary(env, argv[1], &msg) || msg.size == 0 || msg.size > 256 ||
      !enif_inspect_iolist_as_binary(env, argv[2], &sig) || sig.size != 64) {
    return enif_make_badarg(env);
  }

  if (curve25519_verify(sig.data, pk.data, msg.data, msg.size)) {
    return enif_make_atom(env, "false");
  } else {
    return enif_make_atom(env, "true");
  }
}

static ErlNifFunc nif_funcs[] = {
  {"make_private", 1, make_private_nif},
  {"make_public", 1, make_public_nif},
  {"make_shared", 2, make_shared_nif},
  {"sign", 3, sign_nif},
  {"verify", 3, verify_nif},
  {"key_pair", 1, key_pair_nif}
};

static int load(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
  return 0;
}

static int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM load_info)
{
  return 0;
}

static void unload(ErlNifEnv* env, void* priv)
{
  return;
}

ERL_NIF_INIT(curve25519, nif_funcs, &load, NULL, &upgrade, &unload)
