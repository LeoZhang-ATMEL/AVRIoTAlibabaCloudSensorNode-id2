/*
\file   main.c

\brief  Main source file.

(c) 2018 Microchip Technology Inc. and its subsidiaries.

Subject to your compliance with these terms, you may use Microchip software and any
derivatives exclusively with Microchip products. It is your responsibility to comply with third party
license terms applicable to your use of third party software (including open source software) that
may accompany Microchip software.

THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY
IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS
FOR A PARTICULAR PURPOSE.

IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP
HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO
THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL
CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT
OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS
SOFTWARE.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "application_manager.h"
#include "led.h"
#include "sensors_handling.h"
#include "cloud/cloud_service.h"
#include "debug_print.h"
#include "cloud/ali_id2_authen.h"

#include "cryptoauthlib/lib/cryptoauthlib.h"
// This handles messages published from the MQTT server when subscribed

void receivedFromCloud(uint8_t *topic, uint8_t *payload)
{
	char *toggleToken = "\"YellowLEDStatus\":";
	char *subString;

	if ((subString = strstr((char *)payload, toggleToken))) {
		LED_holdYellowOn(subString[strlen(toggleToken)] == '1');
	}

	debug_printer(SEVERITY_NONE, LEVEL_NORMAL, "topic: %s", topic);
	debug_printer(SEVERITY_NONE, LEVEL_NORMAL, "payload: %s", payload);
}

// This will get called every 1 second only while we have a valid Cloud connection

void sendToCloud(void)
{
	static char json[200];

	// This part runs every CFG_SEND_INTERVAL seconds
	int     rawTemperature  = SENSORS_getTempValue();
	int     light           = SENSORS_getLightValue();
	uint8_t ledYellowStatus = LED_Yellow_Status();
	// int len = sprintf(json, "{\"id\":\"1\",\"version\":\"1.0\",\"params\":{\"Status\":1,\"Data\":\"Hello,
	// world!\",\"Light\":%d,\"Temp\":\"%d.%02d\"},\"method\":\"thing.event.property.post\"}",light,rawTemperature/100,abs(rawTemperature)%100);
	int len = sprintf(json,
	"{\"id\":\"1\",\"version\":\"1.0\",\"params\":{\"YellowLEDStatus\":%u,\"Light\":%d,\"Temp\":\"%d."
	"%02d\"},\"method\":\"thing.event.property.post\"}",
	ledYellowStatus,
	light,
	rawTemperature / 100,
	abs(rawTemperature) % 100);
	if (len > 0) {
		CLOUD_publishData((uint8_t *)json, len);
		// LED_flashYellow();
	}
}

char id2_secret[33] = "2122232425262728292A2B2C";
char id2_aes_secret[33] = {0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,
	                       0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

const char server_random[33] = "55B83408399FA660F05C82E4F25333DC";
const char timestamp[14] = "1512022279204";
const char extra[8] = "abcd1234";
uint8_t decrypt_in[16] = {0xEC,0xE1,0x8C,0xE9,0xB9,0x61,0xAE,0xD7,0x50,0x02,0xA4,0x8E,0xB9,0x95,0x5E,0x44};
uint8_t decrypt_out[16];
uint32_t decrypt_out_len = 16;
uint8_t auth_code[200];
uint32_t auth_code_len;

int main(void)
{
	application_init();

	DEVICE_SECRET_save(id2_secret);
#if 0
	if (id2_write_aes_secret(id2_aes_secret) != 0) {
		printf("id2_write_aes_secret failed\r\n");
		while (1) {
			
		}
	}
#endif
	//if (atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, id2_aes_secret, 32) != ATCA_SUCCESS) {
	if (atcab_nonce(id2_aes_secret) != ATCA_SUCCESS) {
		printf("id2_write_aes_secret failed\r\n");
		while (1) {

		}
	}
	
	printf("server_random = 55B83408399FA660F05C82E4F25333DC \r\n");
	id2_client_get_challenge_auth_code(server_random,NULL,0,auth_code,&auth_code_len);
	printf("auth_code: %s\r\n", auth_code);
	
	printf("extra = %s\r\n", extra);
	id2_client_get_challenge_auth_code(server_random,extra,8,auth_code,&auth_code_len);
	
	printf("auth_code: %s\r\n", auth_code);
	
	//printf("test id2_client_get_challenge_auth_code(...)\r\n");
	printf("timestamp = %s, extra = NULL\r\n",timestamp);
	id2_client_get_timestamp_auth_code(timestamp,NULL,0,auth_code,&auth_code_len);
	printf("auth_code: %s\r\n", auth_code);
	
	printf("extra = %s\r\n", extra);
	id2_client_get_timestamp_auth_code(timestamp,extra,8,auth_code,&auth_code_len);
	printf("auth_code: %s\r\n", auth_code);
	
	id2_client_decrypt(decrypt_in,16,decrypt_out,&decrypt_out_len);
	
	while (1) {
		//runScheduler();
	}

	return 0;
}