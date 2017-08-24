/*
 connect.c
 Copyright (c) 2017 DIY Life. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
  Created on: Aug 24, 2017
       Author: Amr Elsayed
 */

#include "sql_connector.h"
#include "connect.h"
#include "lwip/debug.h"


sqlc_descriptor sd;

// two states (init , loop)
enum connect_states{
	CONNECT_INIT,
	CONNECT_LOOP
};

const char hostname[] = "192.168.1.69";
const char username[] = "arduino";
const char password[] = "password";

enum connect_states cs = CONNECT_INIT;
void connect_periodic_handler(void)
{
	int ret = 0 ;
	char connected = 0 ;
	switch(cs){

		case CONNECT_INIT:
			ret = sqlc_create(&sd);
			if(!ret){
				ret = sqlc_connect(&sd,hostname,3306,username,password);
				if(!ret)
					cs = CONNECT_LOOP;
				else{
					sqlc_delete(&sd);
				}
			}

			break;

		case CONNECT_LOOP:
			sqlc_is_connected(&sd,&connected);
			if(connected){
				// success , celebrate...
				 LWIP_DEBUGF(LWIP_DBG_ON, ("connect_periodic_handler():Connected\n\r"));


			}
			break;

	}



}
