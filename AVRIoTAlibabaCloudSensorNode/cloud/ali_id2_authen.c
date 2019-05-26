/*
 * ali_id2_authen.c
 *
 * Created: 2019/5/17 10:34:02
 *  Author: A41547
 */ 
#include "ali_id2_authen.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <atomic.h>
#include "cloud_service.h"
#include "cloud/bsd_adapter/bsdWINC.h"
#include "config/IoT_Sensor_Node_config.h"
#include "cloud/crypto_client/crypto_client.h"
#include "cloud/crypto_client/cryptoauthlib_main.h"
#include "debug_print.h"
#include "include/timeout.h"
#include "cloud/mqtt_packetPopulation/mqtt_packetPopulate.h"
#include "mqtt/mqtt_core/mqtt_core.h"
#include "wifi_service.h"
#include "../cryptoauthlib/lib/jwt/atca_jwt.h"
#include "../cryptoauthlib/lib/tls/atcatls.h"

static uint8_t s_id2_client_inited_flag = false;

/* Fixed POP Header, Total 325 */
uint8_t id2_request[1024] = {
	0x50, 0x4f, 0x53, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d,   /* POST / HTTP/1.1. */
	0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,   /* .Accept-Encoding */
	0x3a, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x0d, 0x0a, 0x78, 0x2d, 0x73, 0x64,   /* : identity..x-sd */
	0x6b, 0x2d, 0x69, 0x6e, 0x76, 0x6f, 0x6b, 0x65, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x6e,   /* k-invoke-type: n */
	0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x61,   /* ormal..Accept: a */
	0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x6d, 0x6c, 0x0d, 0x0a,   /* pplication/xml.. */
	0x78, 0x2d, 0x73, 0x64, 0x6b, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x4a, 0x61,   /* x-sdk-client: Ja */
	0x76, 0x61, 0x2f, 0x32, 0x2e, 0x30, 0x2e, 0x30, 0x0d, 0x0a, 0x43, 0x61, 0x63, 0x68, 0x65, 0x2d,   /* va/2.0.0..Cache- */
	0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68,   /* Control: no-cach */
	0x65, 0x0d, 0x0a, 0x50, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x61,   /* e..Pragma: no-ca */
	0x63, 0x68, 0x65, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a,   /* che..User-Agent: */
	0x20, 0x4a, 0x61, 0x76, 0x61, 0x2f, 0x31, 0x2e, 0x38, 0x2e, 0x30, 0x5f, 0x31, 0x36, 0x32, 0x0d,   /*  Java/1.8.0_162. */
	0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x69, 0x64, 0x32, 0x2e, 0x63, 0x6e, 0x2d, 0x73, 0x68,   /* .Host: id2.cn-sh */
	0x61, 0x6e, 0x67, 0x68, 0x61, 0x69, 0x2e, 0x61, 0x6c, 0x69, 0x79, 0x75, 0x6e, 0x63, 0x73, 0x2e,   /* anghai.aliyuncs. */
	0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a,   /* com..Connection: */
	0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a, 0x43, 0x6f, 0x6e,   /*  keep-alive..Con */
	0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69,   /* tent-type: appli */
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x2d, 0x77, 0x77, 0x77, 0x2d, 0x66, 0x6f, 0x72,   /* cation/x-www-for */
	0x6d, 0x2d, 0x75, 0x72, 0x6c, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x0d, 0x0a, 0x43, 0x6f,   /* m-urlencoded..Co */
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x33, 0x32,   /* ntent-Length: 32 */
	0x35, 0x0d, 0x0a, 0x0d, 0x0a                                                                     /* 3....            */
};

// TODO
// Test Data:
// ACCESS_KEY = "LTAIXQlg58OsZV6X"
// ACCESS_SECRET(Store in Slot, used for hmac-sha1) = "A7VpZJDQYmzAfa9YpbcagCjL46bNFL"
// String id2 = "00FFFF00FFFFFF073EC5AC00";
// String authCode = "0~0~6C15FE4F5C681040~F864CFED7EB2F58C60D2F960FA24407D~0V6nSG7yh7goaIIZyCHMiz4mvDTh2GH0dPbFKYhbaCY=";
// String extra = "digest1234";
// String apiVersion = "1.1.2";
// String productKey = "r5oWHGVkfIw";
// String id2 Password (Store in slot, used for AEC128) = WgozbTh8rQG/ER9O1AluLQ==

void updateID2(void)
{
	
}
void connectID2(void)
{
	
	//uint32_t currentTime = time(NULL);

	// if (currentTime > 0)
	//{
	// The JWT takes time in UNIX format (seconds since 1970), AVR-LIBC uses seconds from 2000 ...
	//updateJWT(currentTime + UNIX_OFFSET);
	//MQTT_CLIENT_connect();
	//}
	//debug_print("CLOUD: MQTT Connect");

	// MQTT SUBSCRIBE packet will be sent after the MQTT connection is established.
	//sendSubscribe = true;
}

// TODO
irot_result_t id2_client_init(void)
{
	// 
	
	return IROT_SUCCESS;
}

irot_result_t id2_client_get_version(uint32_t* pversion)
{
    irot_result_t ret = IROT_SUCCESS;
    if (s_id2_client_inited_flag != true)
    {
	    //id2_log_error("ERROR: [%s] id2 client not inited.\n", __FUNC_NAME__);
	    ret = IROT_ERROR_GENERIC;
    }
    else
    {
	    *pversion = ID2_CLIENT_VERSION_NUMBER;
    }
    return ret;
}

uint8_t id2_write_aes_secret(const uint8_t *data)
{

	ATCA_STATUS status = ATCA_SUCCESS;

	//int retVal = atcab_init(&cfg_ateccx08a_i2c_custom);

	//if (ATCA_SUCCESS != retVal) {
	//	return retVal;
	//}

	status = atcab_write_zone(WRITE_ZONE_DATA, 8, 0, 0, data, ATCA_BLOCK_SIZE);

	if (status == ATCA_SUCCESS) {

		} else {
		return ERROR;
	}

	return NO_ERROR;
}
// TODO
irot_result_t id2_client_get_id(uint8_t* id, uint32_t* len)
{
	// Return, ID2 String
	
	// Return, ID2 read from ATECC608
	// Test Data: 2122232425262728292A2B2C
	//memcpy()
		
		
	ATCA_STATUS status = ATCA_SUCCESS;

	int retVal = atcab_init(&cfg_ateccx08a_i2c_custom);

	if (ATCA_SUCCESS != retVal) {
		return retVal;
	}

	//status = atcab_write_zone(WRITE_ZONE_DATA, 15, 0, 0, data, ATCA_BLOCK_SIZE);
	status = atcab_read_zone(ATCA_ZONE_DATA, 15, 0, 0, id, ATCA_BLOCK_SIZE);
		

	if (status == ATCA_SUCCESS) {
			*len = ID2_ID_LEN;
		} else {
			*len = 0;
		return ERROR;
	}

	//return NO_ERROR;
	return IROT_SUCCESS;

}

// TODO
irot_result_t id2_hash(uint8_t* sign_in, uint32_t sign_in_len, uint8_t* hash_buf, uint32_t* hash_len)
{
	// Return hash result
	// Example??
	// Sign_in = POST&%2F&AccessKeyId%3DLTAIXQlg58OsZV6X%26Action%3DVerify%26ApiVersion%3D1.1.2%26AuthCode%3D0~0~6C15FE4F5C681040~F864CFED7EB2F58C60D2F960FA24407D~0V6nSG7yh7goaIIZyCHMiz4mvDTh2GH0dPbFKYhbaCY%253D%26Extra%3Ddigest1234%26Format%3DXML%26Id2%3D00FFFF00FFFFFF073EC5AC00%26ProductKey%3Dr5oWHGVkfIw%26RegionId%3Dcn-shanghai%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3D579f7d09-b47b-443f-b0ab-1f80d2795fa0%26SignatureVersion%3D1.0%26Timestamp%3D2019-05-20T01%253A55%253A50Z%26Version%3D2017-07-07
	// Password (should be store in ATECC608 slot) = A7VpZJDQYmzAfa9YpbcagCjL46bNFL&
	// 413756705A4A4451596D7A41666139597062636167436A4C3436624E464C26
	// hash_buf out = TWE79uUGbBU2ZLExfI3FCKV0XnU=
	// Can be verified at https://1024tools.com/hmac
	

	
	// Return hash result
	// Example:
	// Sign_in = 2122232425262728292A2B2CABABABABABABABAB55B83408399FA660F05C82E4F25333DC
	// sign_in_len = 0x48
	// hash_buf out = 920EAACDADE8AF10B7154173C2F92E697B2B7C0C6A4A923E6097A823D3B0D9CD
	// Can be verified at https://www.browserling.com/tools/all-hashes
		
	ATCA_STATUS status = ATCA_SUCCESS;

	int retVal = atcab_init(&cfg_ateccx08a_i2c_custom);

	if (ATCA_SUCCESS != retVal) {
		return retVal;
	}

	atcab_hw_sha2_256(sign_in, sign_in_len,hash_buf);
	*hash_len = 32;
			
	return IROT_SUCCESS;
		
		
}

//#define ID2_ID_LEN
// TODO: Get Auth code by challenge
uint8_t result[100];
void hexstr2byte(uint8_t* hexstring, uint8_t len, uint8_t* hexbyte)
{
	uint8_t highbyte,lowbyte;
	uint8_t* pstr = hexstring;
	uint8_t* pbyte = hexbyte;
	
	for(uint8_t i = 0; i < len; i += 2)
	{
		highbyte = *pstr;
		lowbyte = *(pstr+1);
	
		if( highbyte <= 0x39){
			highbyte -= 0x30;
		}else if(highbyte >= 0x41 ){
			highbyte -= 0x37;
		}
	
		if( lowbyte <= 0x39){
			lowbyte -= 0x30;
		}else if(lowbyte >= 0x41 ){
			lowbyte -= 0x37;
		}
	
		*pbyte = (highbyte << 4) | lowbyte;
		pstr += 2;
		pbyte++;
	}
	
}
void byte2hexstr(uint8_t* hexbyte,uint8_t len,uint8_t* hexstring)
{
	uint8_t highbyte,lowbyte;
	uint8_t* pstr = hexstring;
	uint8_t* pbyte = hexbyte;
	
	for(uint8_t i = 0; i < len; i++){
		highbyte = (*pbyte) >> 4;
		lowbyte = (*pbyte) & 0x0F;
		if(highbyte <= 9){
			*pstr = highbyte + 0x30;
		}else if(highbyte >= 0x0A){
			*pstr = highbyte + 0x37;
		}
			
		if(lowbyte <= 9){
			*(pstr+1) = lowbyte + 0x30;
		}else if(lowbyte >= 0x0A){
			*(pstr+1) = lowbyte + 0x37;
		}
			
		pstr += 2;
		pbyte++;
	}
}

irot_result_t id2_client_get_challenge_auth_code(const char* server_random, const uint8_t* extra, uint32_t extra_len, uint8_t* auth_code, uint32_t* auth_code_len)
{
	// Test Data 1:
	// server_random = "55B83408399FA660F05C82E4F25333DC"
	// extra = NULL
	// extra_len = 0
	// authen_code (output) = 0~2~ABABABABABABABAB~55B83408399FA660F05C82E4F25333DC~4sx4q/vZtJeBciBhpfzBwLaw7kXg4s2mmZxSoehsKtyXnA1nt3r97vPi1Bnh6fF1
	// authen_code (output) = 118
	
	// Test Data 2
	// server_random = "55B83408399FA660F05C82E4F25333DC"
	// extra = "abcd1234"
	// extra_len = 8
	// authen_code (output) = 2~2~ABABABABABABABAB~55B83408399FA660F05C82E4F25333DC~PdEkTetZVHtD3+o64apuEnsgzwkqbJMfTJSMaHTSYFKXnA1nt3r97vPi1Bnh6fF1
	// authen_code (output) = 118
	
	// Step 1:  Generate Signature input data: ID2 + Random + Challenge + extra
	// Result: 2122232425262728292A2B2CABABABABABABABAB55B83408399FA660F05C82E4F25333DC (Test 1)
	// Result: 2122232425262728292A2B2CABABABABABABABAB55B83408399FA660F05C82E4F25333DCabcd1234 (Test 2)
	//*
	ATCA_STATUS status = ATCA_SUCCESS;
	uint32_t len = 100;
	uint32_t len1 = 16;
	uint16_t templen, templ;
	uint8_t sign_in[128];
	uint8_t temp[32];
	uint16_t sign_in_len;
	uint16_t authcodelen;
	
	id2_client_get_id(sign_in,&len);
	if(len != (ID2_ID_LEN)){
		//ID2_ID_LEN is 24
		//ID2 ID length error 
	}
	
	id2_client_get_device_challenge((uint8_t*)(sign_in + ID2_ID_LEN),&len1); //device challenge length is 16
	memcpy((uint8_t*)(auth_code + 4), (uint8_t*)(sign_in + ID2_ID_LEN), len1);
	authcodelen = 4+len1;
	*(auth_code + authcodelen) = '~';
	authcodelen++;
	
	templen = ID2_ID_LEN  + len1;
	
	templ = strlen(server_random);
	memcpy((uint8_t*)(sign_in + templen), server_random, templ);
	templen += templ;
	
	memcpy((uint8_t*)(auth_code + authcodelen), server_random, templ);
	authcodelen += templ;
	
	*(auth_code + authcodelen) = '~';
	authcodelen++;
	
	auth_code[0] = '0';
	auth_code[1] = '~';
	auth_code[2] = '2';
	auth_code[3] = '~';

	if((extra != NULL) && (extra_len > 0)){
		memcpy((sign_in + templen),extra,extra_len);
		templen += extra_len;
		auth_code[0] += 2;
	}
	sign_in_len = templen;

	// Step 2: hash Signature by invoke id2_hash
	// Result: 920EAACDADE8AF10B7154173C2F92E697B2B7C0C6A4A923E6097A823D3B0D9CD (Test 1)
	// Result: 157888C53414377BAB744339E069D354039F6EA9C73B0C000714C4BAF4A8E3F8 (Test 2)

	atcab_hw_sha2_256(sign_in, sign_in_len,result);
	
	// Step 3: Signature padding
	// Result: 920EAACDADE8AF10B7154173C2F92E697B2B7C0C6A4A923E6097A823D3B0D9CD10101010101010101010101010101010 (Test 1)
	// Result: 157888C53414377BAB744339E069D354039F6EA9C73B0C000714C4BAF4A8E3F810101010101010101010101010101010 (Test 2)
	
	memset((result + 32),0x10,16);
	
	// Step 4: AES Encrypt ???Signature with padding) password 2122232425262728292A2B2C2D2E2F30, can be verify at http://www.cryptogrium.com/aes-encryption-online-ecb.html
	// Result: E2CC78ABFBD9B49781722061A5FCC1C0B6B0EE45E0E2CDA6999C52A1E86C2ADC979C0D67B77AFDEEF3E2D419E1E9F175 (Test 1)
	// Result: 3DD1244DEB59547B43DFEA3AE1AA6E127B20CF092A6C931F4C948C6874D26052979C0D67B77AFDEEF3E2D419E1E9F175 (Test 2)
	
	extern char id2_aes_secret[33];
	atcab_nonce(id2_aes_secret); /* Only TEMPKEY need to be write before AES command */

	status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID,0,result,sign_in);
	if (status != ATCA_SUCCESS) {
		return status;
	}
	status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID,0,(result+16),(sign_in+16));
	if (status != ATCA_SUCCESS) {
		return status;
	}
	status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID,0,(result+32),(sign_in+32));
	if (status != ATCA_SUCCESS) {
		return status;
	}
	
	// Step 5: Base64 (Can be verified at https://conv.darkbyte.ru/)
	// Result(ASCII): 4sx4q/vZtJeBciBhpfzBwLaw7kXg4s2mmZxSoehsKtyXnA1nt3r97vPi1Bnh6fF1 (Test 1)
	// Result(ASCII): PdEkTetZVHtD3+o64apuEnsgzwkqbJMfTJSMaHTSYFKXnA1nt3r97vPi1Bnh6fF1 (Test 2)
	len = 100;
	atcab_base64encode(sign_in,48,result,&len);
	
	memcpy((uint8_t*)(auth_code + authcodelen), result, 64);
	authcodelen += 64;
	*auth_code_len = authcodelen;
	
	return IROT_SUCCESS;
}

// TODO: Get Auth code by Timestamp
irot_result_t id2_client_get_timestamp_auth_code(const char* timestamp, const uint8_t* extra, uint32_t extra_len, uint8_t* auth_code, uint32_t* auth_code_len)
{
	// Test Data 1:
	// timestamp = "1512022279204"
	// extra = NULL
	// extra_len = 0
	// authen_code (output) = 1~2~ABABABABABABABAB~1512022279204~8WFAQalYm+5++M4OKMtH2JOqsvOlS67rsX9ccSRpvWSXnA1nt3r97vPi1Bnh6fF1
	// authen_code (output) = 99
	
	// Test Data 2
	// server_random = "1512022279204"
	// extra = "abcd1234"
	// extra_len = 8
	// authen_code (output) = 3~2~ABABABABABABABAB~1512022279204~3vxizdS0JVOKSqnsR8VsZd0xUnL7Uo2S4ojSgXnoxI6XnA1nt3r97vPi1Bnh6fF1
	// authen_code (output) = 99
	
	// Step 1:  Generate Signature input data: ID2 + Challenge + Timestamp + extra
	// Result: 2122232425262728292A2B2CABABABABABABABAB1512022279204 (Test 1)
	// Result: 2122232425262728292A2B2CABABABABABABABAB1512022279204abcd1234 (Test 2)
	
	// Step 2: hash Signature by invoke id2_hash
	// Result: 47349A522BB85BA0D20F10B964865DCF52CD13FF3C8B83C93E51D97A95042AFD (Test 1)
	// Result: 1140825D382FDA6B00D859CD2A73486FB8DDEE69C591BACD490BF2703979C628 (Test 2)
	
	// Step 3: Signature padding
	// Result: 47349A522BB85BA0D20F10B964865DCF52CD13FF3C8B83C93E51D97A95042AFD10101010101010101010101010101010 (Test 1)
	// Result: 1140825D382FDA6B00D859CD2A73486FB8DDEE69C591BACD490BF2703979C62810101010101010101010101010101010 (Test 2)
	
	// Step 4: AES Encrypt ???Signature with padding) password 2122232425262728292A2B2C2D2E2F30, can be verify at http://www.cryptogrium.com/aes-encryption-online-ecb.html
	// Result: F1614041A9589BEE7EF8CE0E28CB47D893AAB2F3A54BAEEBB17F5C712469BD64979C0D67B77AFDEEF3E2D419E1E9F175 (Test 1)
	// Result: DEFC62CDD4B425538A4AA9EC47C56C65DD315272FB528D92E288D28179E8C48E979C0D67B77AFDEEF3E2D419E1E9F175 (Test 2)
	
	// Step 5: Base64 (Can be verified at https://conv.darkbyte.ru/)
	// Result(ASCII): 8WFAQalYm+5++M4OKMtH2JOqsvOlS67rsX9ccSRpvWSXnA1nt3r97vPi1Bnh6fF1 (Test 1)
	// Result(ASCII): 3vxizdS0JVOKSqnsR8VsZd0xUnL7Uo2S4ojSgXnoxI6XnA1nt3r97vPi1Bnh6fF1 (Test 2)
	id2_client_get_challenge_auth_code(timestamp,extra,extra_len,auth_code,auth_code_len);
	auth_code[0] += 1;

	return IROT_SUCCESS;	

}

/**
 * TODO decrypt the input data with ID2 key.
 */
irot_result_t id2_client_decrypt(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len)
{
	// in = ECE18CE9B961AED75002A48EB9955E44
	// out = 313233340C0C0C0C0C0C0C0C0C0C0C0C
	ATCA_STATUS status = ATCA_SUCCESS;	
	status = atcab_aes_decrypt(8,0,in,out);
	if (status != ATCA_SUCCESS) {
		return status;
	}
	return IROT_SUCCESS;
}

/**
 * TODO get the challenge form device.
 */
irot_result_t id2_client_get_device_challenge(uint8_t* device_random_buf, uint32_t* device_random_len)
{
	// (Test Data) return 0xABABABAB......
	// use ATECC608 random value
	uint8_t i;
	uint8_t device_random_byte[8];
	
	for (i = 0; i < 8; ++i) {
		device_random_byte[i] = (uint8_t)0xAB;
	}
	
	byte2hexstr(device_random_byte,8,device_random_buf);
	*device_random_len = 16;
	
	return IROT_SUCCESS;
}

/**
 * TODO   verify the auth code from server.
 */
irot_result_t id2_client_verify_server(const uint8_t* server_auth_code, uint32_t server_auth_code_len, const uint8_t* device_random, uint32_t device_random_len, const uint8_t* server_extra, uint32_t server_extra_len)
{
	return IROT_SUCCESS;
}