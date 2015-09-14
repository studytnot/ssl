#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>

static int bind_fn(ENGINE * e, const char *id)
{
      if (!ENGINE_set_id(e, "simple") ||
              !ENGINE_set_name(e, "simple engine")) {
              return 0;

      } else {
              return 1;

      }

}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn);
