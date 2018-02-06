#define HAVE_AES_KEYWRAP
#define HAVE_X963_KDF
#define WOLFSSL_AES_DIRECT
#define HAVE_PKCS7
#define FOURK_BUF 4096

#include <wolfssl\wolfcrypt\pkcs7.h>
#include <wolfssl\wolfcrypt\error-crypt.h>
#include <wolfssl\wolfcrypt\hash.h>

void generatePKCS7(byte* content, byte* contentSize);