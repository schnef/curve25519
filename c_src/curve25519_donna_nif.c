/*
 * Frans Schneider
 * Public domain.
 * 
 * Got inspiration from http://erlang.org/pipermail/erlang-questions/2011-April/057954.html
 */

#include <string.h>
#include "erl_nif.h"

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

static ErlNifFunc nif_funcs[] = {
  {"make_private", 1, make_private_nif},
  {"make_public", 1, make_public_nif},
  {"make_shared", 2, make_shared_nif},
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
