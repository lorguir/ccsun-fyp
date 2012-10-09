/*
 * Based on the work of Romain Tartiere & Romuald Conty <http://code.google.com/p/nfc-tools/wiki/libfreefare>
 *
 * Copyright (C) 2012 UCTI Sdn Bhd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * 
 * Author: Daniel Leom
 */
 
#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <math.h>
#include <mysql/mysql.h>
#include "common.h"

#include <nfc/nfc.h>

#include <freefare.h>

#define MIN(a,b) ((a < b) ? a: b)

#include <time.h> //for benchmark
#define BILLION  1E9

MifareClassicKey default_keys[] = {
    { 0xff,0xff,0xff,0xff,0xff,0xff },
    { 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
    { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
    { 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
    { 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
    { 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
    { 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
    { 0x00,0x00,0x00,0x00,0x00,0x00 }
};

struct mifare_classic_key_and_type {
    MifareClassicKey key;
    MifareClassicKeyType type;
};

const MifareClassicKey default_keyb = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};

const uint8_t ndef_default_msg[33] = {
    0xd1, 0x02, 0x1c, 0x53, 0x70, 0x91, 0x01, 0x09,
    0x54, 0x02, 0x65, 0x6e, 0x4c, 0x69, 0x62, 0x6e,
    0x66, 0x63, 0x51, 0x01, 0x0b, 0x55, 0x03, 0x6c,
    0x69, 0x62, 0x6e, 0x66, 0x63, 0x2e, 0x6f, 0x72,
    0x67
};

int
search_sector_key (MifareTag tag, MifareClassicSectorNumber sector, MifareClassicKey *key, MifareClassicKeyType *key_type)
{
    MifareClassicBlockNumber block = mifare_classic_sector_last_block (sector);

    /*
     * FIXME: We should not assume that if we have full access to trailer block
     *        we also have a full access to data blocks.
     */
    mifare_classic_disconnect (tag);
    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
		if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
			if ((1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYA, MFC_KEY_A)) &&
				(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A)) &&
				(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYB, MFC_KEY_A))) {
					memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
					*key_type = MFC_KEY_A;
					return 1;
			}
		}
		mifare_classic_disconnect (tag);

		if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
			if ((1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYA, MFC_KEY_B)) &&
				(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B)) &&
				(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYB, MFC_KEY_B))) {
					memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
					*key_type = MFC_KEY_B;
					return 1;
			}
		}
		mifare_classic_disconnect (tag);
    }

    warnx ("No known authentication key for sector 0x%02x\n", sector);
    return 0;
}

int
fix_mad_trailer_block (nfc_device_t *device, MifareTag tag, MifareClassicSectorNumber sector, MifareClassicKey key, MifareClassicKeyType key_type)
{
    MifareClassicBlock block;
    mifare_classic_trailer_block (&block, mad_public_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, default_keyb);
    if (mifare_classic_authenticate (tag, mifare_classic_sector_last_block (sector), key, key_type) < 0) {
		nfc_perror (device, "fix_mad_trailer_block mifare_classic_authenticate");
		return -1;
    }
    if (mifare_classic_write (tag, mifare_classic_sector_last_block (sector), block) < 0) {
		nfc_perror (device, "mifare_classic_write");
		return -1;
    }
    return 0;
}

uint8_t ndef_msg[20] = {0};
size_t  ndef_msg_len;

int
main(int argc, char *argv[])
{

	char ndef_input[15] = {'\0'};
	
	MYSQL *conn;
	MYSQL_RES *result;
	MYSQL_ROW row;
	MYSQL_FIELD *field;
	int retval;
	
	conn = mysql_init(NULL);
	
	retval = mysql_real_connect(conn, def_host_name, def_user_name, def_password, def_db_name, def_port_num, def_socket_name, def_client_flag);
	if(!retval)
	{
		printf("Error connecting to database: %s\n", mysql_error(conn));
		return -1;
	}
	printf("Connection successful\n");
    
    int error = 0;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;
    Mad mad;

    nfc_device_desc_t devices[8];
    size_t device_count;

    nfc_list_devices (devices, 8, &device_count);
    if (!device_count)
	errx (EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; d < device_count; d++) 
	{
		device = nfc_connect (&(devices[d]));
		if (!device) {
			warnx ("nfc_connect() failed.");
			error = EXIT_FAILURE;
			continue;
		}

		tags = freefare_get_tags (device);
		if (!tags) {
			nfc_disconnect (device);
			errx (EXIT_FAILURE, "Error listing MIFARE classic tag.");
		}

		for (int i = 0; (!error) && tags[i]; i++) {
			switch (freefare_get_tag_type (tags[i])) {
				case CLASSIC_1K:
				case CLASSIC_4K:
					break;
				default:
					continue;
			}

			char *tag_uid = freefare_get_tag_uid (tags[i]);
			char buffer[BUFSIZ];

			printf ("Found %s with UID %s.\n", freefare_get_tag_friendly_name (tags[i]), tag_uid);

			// NFCForum card has a MAD, load it.
			if (mifare_classic_connect (tags[i]) == 0) {
			} else {
				nfc_perror (device, "mifare_classic_connect");
				error = EXIT_FAILURE;
				goto error;
			}

			if ((mad = mad_read (tags[i]))) 
			{
				// Dump the NFCForum application using MAD information
				uint8_t buffer[4096];
				ssize_t len;
				if ((len = mifare_application_read (tags[i], mad, mad_nfcforum_aid, buffer, sizeof(buffer), mifare_classic_nfcforum_public_key_a, MFC_KEY_A)) != -1) 
				{
					uint8_t tlv_type;
					uint16_t tlv_data_len;
					
					uint8_t * tlv_data = tlv_decode (buffer, &tlv_type, &tlv_data_len);
					switch (tlv_type) 
					{
						case 0x00:
							fprintf (stderr, "NFCForum application contains a \"NULL TLV\".\n");	// FIXME: According to [ANNFC1K4K], we should skip this TLV to read further TLV blocks.
							error = EXIT_FAILURE;
							goto error;
							break;
						case 0x03:
							printf ("NFCForum application contains a \"NDEF Message TLV\".\n");
							break;
						case 0xFD:
							fprintf (stderr, "NFCForum application contains a \"Proprietary TLV\".\n");	// FIXME: According to [ANNFC1K4K], we should skip this TLV to read further TLV blocks.
							error = EXIT_FAILURE;
							goto error;
							break;
						case 0xFE:
							fprintf (stderr, "NFCForum application contains a \"Terminator TLV\", no available data.\n");
							error = EXIT_FAILURE;
							goto error;
							break;
						default:
							fprintf (stderr, "NFCForum application contains an invalid TLV.\n");
							error = EXIT_FAILURE;
							goto error;
							break;
					}
					
					int i=0, j=0;
					char ID[9] = {'\0'};
					
					for(i=0;i<8;i++)
						ID[i] = tlv_data[i];
					
					ulong uid_length = strlen(tag_uid);
					char uid_esc[(2 * uid_length)+1];

					mysql_real_escape_string(conn, uid_esc, tag_uid, uid_length);
					char sql_stmnt[52] = {'\0'};
					int n = 0;
					
					n = snprintf(sql_stmnt, 52, "SELECT student_id FROM student WHERE uid='%s'", uid_esc);
					retval = mysql_real_query(conn, sql_stmnt, n);
					if(retval)
					{
						printf("Select data from DB Failed\n");
						return -1;
					}
					printf("Select to DB successful\n");
					
					char *ID_db = NULL;
					
					result = mysql_store_result(conn);
					while (row = mysql_fetch_row(result)) {
						ID_db = row[0];
					}
					
					if(ID_db == NULL)
					{
						printf("\nNo user found\n");
						exit(EXIT_SUCCESS);
					}
					//validate owner of the card
					else if(strcmp(ID, ID_db) != 0)
					{
						printf("\nStudent found but not match to database\n");
						exit(EXIT_SUCCESS);
					}
					else
					{
						printf("\nStudent found: %s\n", ID_db);
						
						ulong id_length = strlen(ID);
						char id_esc[(2 * id_length)+1];

						mysql_real_escape_string(conn, id_esc, ID, id_length);
						char sql_stmnt[56] = {'\0'};
						int n = 0;
						
						n = snprintf(sql_stmnt, 56, "SELECT balance FROM student WHERE student_id='%s'", id_esc);
						retval = mysql_real_query(conn, sql_stmnt, n);
						if(retval)
						{
							printf("Select data from DB Failed\n");
							return -1;
						}
						printf("Select to DB successful\n");
						
						double balance_db = 0;
						
						result = mysql_store_result(conn);

						while(field = mysql_fetch_field(result))
						{
							if(field->type == MYSQL_TYPE_NEWDECIMAL)
							{
								while (row = mysql_fetch_row(result))
								{
									balance_db = atof(row[0]);
								}
							}
							else
							{
								printf("The field contains non-numeric data.\n");
							}
						}
						
						//compare balance from database with balance from card
						char balance_char[6] = {'\0'};
						double balance = 0;
						j=0;
						for(i=8;i<13;i++)
						{
							balance_char[j] = tlv_data[i];
							j++;
						}
							
						balance = atof(balance_char);
						
						if(balance == balance_db)
						{
							printf("\n\nValid balance\n\n");
							
							//start to check out
							double price = 0;
							printf("\nFood price: RM ");
							scanf("%lf", &price);
							while (getchar() != '\n') continue;
							
							if(balance >= price)
							{
								balance -= price;
								snprintf(balance_char, 6, "%.2f", balance ); 
							}
							else
							{
								printf("\nInsufficient fund.\n");
								printf("\nPress enter to continue.\n");
								getchar();
								exit(EXIT_SUCCESS);
							}
							
							//ensure balance always with 4 digit, 4.00 => 04.00
							char final_balance[6] = {'\0'};
							if(strlen(balance_char) != 5)
							{
								strcat(final_balance, "0");
								strcat(final_balance, balance_char);
							}
							else
								strcpy(final_balance, balance_char);
							
							strcat(ndef_input, ID);
							strcat(ndef_input, final_balance);
							
							//update database														
							char sql_stmnt[60] = {'\0'};
							int n = 0;
							
							n = snprintf(sql_stmnt, 60, "UPDATE student SET balance=%.1f WHERE student_id='%s'", balance, id_esc);
							retval = mysql_real_query(conn, sql_stmnt, n);
							if(retval)
							{
								printf("Updating data from DB Failed\n");
								return -1;
							}
							else
							{
								printf("Update successful\n");
								
								//log activity into database
								char sql_stmnt[50] = {'\0'};
								int n = 0;
								
								n = snprintf(sql_stmnt, 50, "INSERT INTO sales VALUES(NOW(), %.1f, '%s')", price, uid_esc);
								retval = mysql_real_query(conn, sql_stmnt, n);
								if(retval)
								{
									printf("Inserting data from DB Failed\n");
									return -1;
								}
								printf("Insert to DB successful\n");
							}
						}
						else
						{
							printf("\n\nInvalid balance\n\n");
						}
					}
					
					free (tlv_data);
				} else {
					fprintf (stderr, "No NFC Forum application.\n");
					error = EXIT_FAILURE;
					goto error;
				}
			} 
			else 
			{
				fprintf (stderr, "No MAD detected.\n");
				error = EXIT_FAILURE;
				goto error;
			}
			free (mad);

			error:
			free (tag_uid);
		}

		freefare_free_tags (tags);
		nfc_disconnect (device);
    }
	
	mysql_free_result(result);
	mysql_close(conn);
	
	if(strlen(ndef_input) != NULL)
	{
		//write back to card
		//assuming ndef_input always have same length
		char command[66] = {'\0'};
		
		strcat(command, "~/Dropbox/Work/libfreefare/examples/simple-write -i ");
		strcat(command, ndef_input);
		
		system(command);
	}

    exit (error);

}
