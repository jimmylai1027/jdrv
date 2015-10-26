#ifndef __AES_H__
#define __AES_H__

void AES128CBC_Init(char *civ, char *cck);

void AES128CBC_CipherEncrypt(char *data, int size);

void AES128CBC_CipherDecrypt(char *data, int size);

#endif /* __AES_H__*/
