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
#include "common.h"
#include <mysql/mysql.h>
#include "common.h"

#include <nfc/nfc.h>

#include <freefare.h>


#define MIN(a,b) ((a < b) ? a: b)


int
main(int argc, char *argv[])
{

	//initilize database
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

    for (size_t d = 0; d < device_count; d++) {
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
			
			//play some sound
			//system ("mplayer -slave -really-quiet ~/Dropbox/Work/sample/test.wav");
			
			printf ("Found %s with UID %s.\n", freefare_get_tag_friendly_name (tags[i]), tag_uid);
			
			// NFCForum card has a MAD, load it.
			if (mifare_classic_connect (tags[i]) == 0) {
			} else {
				nfc_perror (device, "mifare_classic_connect");
				error = EXIT_FAILURE;
				goto error;
			}

			if ((mad = mad_read (tags[i]))) {
				// Dump the NFCForum application using MAD information
				uint8_t buffer[4096];
				ssize_t len;
				if ((len = mifare_application_read (tags[i], mad, mad_nfcforum_aid, buffer, sizeof(buffer), mifare_classic_nfcforum_public_key_a, MFC_KEY_A)) != -1) 
				{
					uint8_t tlv_type;
					uint16_t tlv_data_len;
					
					uint8_t * tlv_data = tlv_decode (buffer, &tlv_type, &tlv_data_len);
					switch (tlv_type) {
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
						printf("\nNo student found\n");
					}
					else if(strcmp(ID, ID_db) != 0)
					{
						printf("\nStudent found but not match to database\n");
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
						
						printf("\nBalance (card): \tRM%.2f", balance);
						printf("\nBalance (database) : \tRM%.2f", (double)balance_db);
						
						if(balance == (double)balance_db)
						{
							printf("\n\nValid balance\n\n");
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
			} else {
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
    exit (error);
}
