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

//to-do: check topup limit


#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include "common.h"

#include <nfc/nfc.h>

#include <freefare.h>


#define START_FORMAT_N	"Formatting %d sectors ["
#define DONE_FORMAT	"] done.\n"

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
int		 format_mifare_classic_1k (MifareTag tag);
int		 format_mifare_classic_4k (MifareTag tag);
int		 try_format_sector (MifareTag tag, MifareClassicSectorNumber sector);

static int at_block = 0;
static int mod_block = 10;

struct {
    bool fast;
    bool interactive;
} format_options = {
    .fast        = false,
    .interactive = true
};

void
display_progress ()
{
    at_block++;
    if (0 == (at_block % mod_block)) {
		printf ("%d", at_block);
		fflush (stdout);
    } else {
		printf (".");
		fflush (stdout);
    }
}

int
format_mifare_classic_1k (MifareTag tag)
{
    printf (START_FORMAT_N, 16);
    for (int sector = 0; sector < 16; sector++) {
		if (!try_format_sector (tag, sector))
			return 0;
    }
    printf (DONE_FORMAT);
    return 1;
}

int
format_mifare_classic_4k (MifareTag tag)
{
    printf (START_FORMAT_N, 32 + 8);
    for (int sector = 0; sector < (32 + 8); sector++) {
		if (!try_format_sector (tag, sector))
			return 0;
    }
    printf (DONE_FORMAT);
    return 1;
}

int
try_format_sector (MifareTag tag, MifareClassicSectorNumber sector)
{
    display_progress ();
    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
		MifareClassicBlockNumber block = mifare_classic_sector_last_block (sector);
		if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
			if (0 == mifare_classic_format_sector (tag, sector)) {
				mifare_classic_disconnect (tag);
				return 1;
			} else if (EIO == errno) {
				err (EXIT_FAILURE, "sector %d", sector);
			}
			mifare_classic_disconnect (tag);
		}

		if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
			if (0 == mifare_classic_format_sector (tag, sector)) {
				mifare_classic_disconnect (tag);
				return 1;
			} else if (EIO == errno) {
				err (EXIT_FAILURE, "sector %d", sector);
			}
			mifare_classic_disconnect (tag);
		}
    }

    warnx ("No known authentication key for sector %d", sector);
    return 0;
}

int
main(int argc, char *argv[])
{
	double balance = 0;
	double rc_balance = 0;
	int found_user = 0;
	char *ID_db = NULL;
	
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
	
	
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;

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
			errx (EXIT_FAILURE, "Error listing Mifare Classic tag.");
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
			
			//get the remaining balance of the user
			ulong uid_length = strlen(tag_uid);
			char uid_esc[(2 * uid_length)+1];

			mysql_real_escape_string(conn, uid_esc, tag_uid, uid_length);
			
			//get student_id
			int n = 0;
			
			n = snprintf(sql_stmnt, 52, "SELECT student_id FROM student WHERE uid='%s'", uid_esc);
			retval = mysql_real_query(conn, sql_stmnt, n);
			if(retval)
			{
				printf("Select data from DB Failed\n");
				return -1;
			}
			printf("Select to DB successful\n");
						
			result = mysql_store_result(conn);
			while (row = mysql_fetch_row(result)) {
				ID_db = row[0];
			}
			
			//exit if card is invalid
			if (ID_db == NULL)
			{
				puts("No user found/Invalid card.");
				exit(EXIT_SUCCESS);
			}
			
			//get balance
			char sql_stmnt[49] = {'\0'};
			n = snprintf(sql_stmnt, 49, "SELECT balance FROM student WHERE uid='%s'", uid_esc);
			retval = mysql_real_query(conn, sql_stmnt, n);
			if(retval)
			{
				printf("Select data from DB Failed\n");
				return -1;
			}
			printf("Select to DB successful\n");
			
			result = mysql_store_result(conn);
			char *cols = NULL;
			
			while(field = mysql_fetch_field(result))
			{
				if(field->type == MYSQL_TYPE_NEWDECIMAL)
				{
					while (row = mysql_fetch_row(result))
					{
						balance = atof(row[0]);
						cols = row[0];
					}
				}
				else
				{
					printf("The field contains non-numeric data.\n");
				}
			}
			
			if (cols == NULL)
			{
				puts("Cannot retrieve balance");
				exit(EXIT_SUCCESS);
			}
			else
			{
				found_user = 1;
			}

			free (tag_uid);
		}

		freefare_free_tags (tags);
		nfc_disconnect (device);
    }
	
	mysql_free_result(result);
	mysql_close(conn);
	
	if(found_user == 1)
	{
		//to-do, simply write database in child process.

		printf("\nPlease place the card. Press Enter to continue.\n");
		while (getchar() != '\n');
		
		char balance_char[6] = {'\0'};
		char final_balance[6] = {'\0'};
		
		snprintf(balance_char, 6, "%.2f", balance);
		
		if(strlen(balance_char) != 5)
		{
			strcat(final_balance, "0");
			strcat(final_balance, balance_char);
		}
		else
		{
			strcpy(final_balance, balance_char);
		}
		
		
		//write back to card
		char command[66] = {'\0'};
		
		strcat(command, "~/Dropbox/Work/libfreefare/examples/simple-write -i ");
		strcat(command, ID_db);
		strcat(command, final_balance);
		
		system(command);
		
	}
	
    exit (error);
}
