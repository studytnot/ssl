/*********************************
 * * dsa_example.c
 * * by Mahacom Aramsereewong
 * * 7/12/2004
 * *
 * *********************************/
#include "stdio.h"
#include "string.h"
#include "openssl/dsa.h"
#include "openssl/engine.h"
#include "openssl/err.h"
#include "openssl/md5.h"

int main() {

/* **************************
 * * SIGNATURE CREATION PART
 * *
 * * *************************/

FILE *ERRfp;
char *ERRbuf = malloc(200);

 Create DSA key
 DSA *dsa = DSA_generate_parameters(1024,NULL,0,NULL,NULL,NULL,NULL);
 if(dsa==NULL) {
 printf("ERROR: Generating DSA_parameter failed.\n");
 DSA_free(dsa);
 exit(0);
  }
  printf("DSA_parameter successfully generated.\t\t\t\t\t[ok]\n");

  if(DSA_generate_key(dsa) == 0) {
  printf("ERROR: Generating DSA_key failed.\n");
  DSA_free(dsa);
  exit(0);
   }
   printf("DSA_key successfully generated.\t\t\t\t\t\t[ok]\n");

   // Print DSA key to file
   FILE *fp;
   if((fp=fopen("DSAkey","w")) == NULL)
   printf("ERROR: Create DSAkey file failed.\n");
   else {
   printf("Creating file DSAkey succeeded.\t\t\t\t\t\t[ok]\n");
   if(DSA_print_fp(fp,dsa,0) != 1)
   printf("ERROR: Write DSAkey to file failed.\n");
   else {
   printf("Writing DSAkey to file completed..\t\t\t\t\t[ok]\n");
   fclose(fp);
    }
     }

     /* Signing digital signature */
     unsigned char *msg = "My email: mahacom.a@student.chula.ac.th";
     unsigned char *md = MD5(msg, strlen(msg), NULL);
     int Siglen;
     unsigned char *Sig = malloc(DSA_size(dsa));
     if((DSA_sign(0, md, strlen(md), Sig, &Siglen, dsa)) != 1) {
     printf("ERROR: Digital signature signing failed.\n");
     DSA_free(dsa);
     exit(0);
      }
      printf("Digital signature successfully signed..\t\t\t\t\t[ok]\n");
      printf("SIGNATURE SIZE:-> %d.\t\t\t\t\t\t\t[ok]\n",Siglen);

      // Convert DSAkey to DER and write to file
      DSA *fdsa = DSA_new();
      fdsa->p = BN_new();
      BN_copy(fdsa->p, dsa->p);
      fdsa->q = BN_new();
      BN_copy(fdsa->q, dsa->q);
      fdsa->g = BN_new();
      BN_copy(fdsa->g, dsa->g);
      fdsa->pub_key = BN_new();
      BN_copy(fdsa->pub_key,dsa->pub_key);
      fdsa->priv_key = NULL;
      unsigned char *buf, *k;
      int x;
      buf = OPENSSL_malloc(i2d_DSAPublicKey(fdsa, NULL));
      k = buf;
      int len = i2d_DSAPublicKey(fdsa, &k);
      if (len < 0) printf("ERROR: Convert DSA to DER failed.\n");
      else printf("Convert DSA to DER succeeded. DER length = %d.\t\t\t\t[ok]\n",len);
      FILE *fpder;
      if((fpder=fopen("DERkey","wb")) == NULL)
      printf("ERROR: Create DERkey file failed.\n");
      else {
      if((x=fwrite(buf, sizeof(char), len, fpder)) < len)
      printf("ERROR: Writing DER = %d character, Not complete.\n",x);
      else
      printf("Writing DER = %d character, Succeeded.\t\t\t\t\t[ok]\n",x);
       }
       fclose(fpder);
       DSA_free(dsa);
       DSA_free(fdsa);

       /* ****************************
       * SIGNATURE VERIFICATION PART
       *
       * ***************************/

       // Convert DER which be read from file back to DSAkey
       FILE *vfp;
       if((vfp=fopen("DERkey","rb")) == NULL) {
       printf("ERROR: Can't open DERkey file.\n");
       exit(0);
        }
        if((x=fread(buf,sizeof(char),len,vfp)) < len)
        printf("ERROR: Read DER = %d character, Not complete.\n",x);
        else
        printf("Read DER = %d character, completed.\t\t\t\t\t[ok]\n",x);
        DSA *vdsa = NULL;
        k = buf;
        if(d2i_DSAPublicKey(&vdsa, &k, len) == NULL) {
        ERR_error_string_n(ERR_get_error(), ERRbuf, 199);
        printf("ERROR: %s\n",ERRbuf);
        if((ERRfp=fopen("ssl_error","w")) == NULL)
        printf("ERROR: can't log the error message into \"ssl_error\" file.\n");
        else {
        ERR_print_errors_fp(ERRfp);
        printf("ERROR: Convert DER to DSA failed. See \"ssl_error\" file for details.\n");
         }
          }
          else
          printf("Convert DER to DSA succeeded.\t\t\t\t\t\t[ok]\n");

          /* Verify digital signature */
          unsigned char *vmsg = "My email: mahacom.a@student.chula.ac.th";
          unsigned char *vmd = MD5(vmsg, strlen(vmsg), NULL);

          if((DSA_verify(0, vmd, strlen(vmd), Sig, Siglen, vdsa)) != 1)
          printf("ERROR: Bad Signature.\n");
          else
          printf("Congratulation! your signature is valid..\t\t\t\t\n");

          DSA_free(vdsa);
          return 0;
          }
