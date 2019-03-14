/*
 sql_connector.h
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
  Created on: Aug 21, 2017
       Author: Amr Elsayed
 */

#ifndef INC_SQL_CONNECTOR_H_
#define INC_SQL_CONNECTOR_H_

#include "lwip/err.h"


#define MYSQL_OK_PACKET     0x00
#define MYSQL_EOF_PACKET    0xfe
#define MYSQL_ERROR_PACKET  0xff



/** Request successfully got */
#define SQLC_RESULT_OK            0
/** Unknown error */
#define SQLC_RESULT_ERR_UNKNOWN   1
/** Connection to server failed */
#define SQLC_RESULT_ERR_CONNECT   2
/** Failed to resolve server hostname */
#define SQLC_RESULT_ERR_HOSTNAME  3
/** Connection unexpectedly closed by remote server */
#define SQLC_RESULT_ERR_CLOSED    4
/** Connection timed out (server didn't respond in time) */
#define SQLC_RESULT_ERR_TIMEOUT   5
/** Server responded with an unknown response code */
#define SQLC_RESULT_ERR_SVR_RESP  6
/** No Enough buffer for Data */
#define SQLC_BUFFER_ERR           7
/** No Enough Memory for TCP_WRITE */
#define SQLC_TCP_MEM_ERR          8

enum error_state {
	CONNECTOR_ERROR_OK,
	CONNECTOR_ERROR_NOT_CONNECTED,
	CONNECTOR_ERROR_UNEXPECTED_CLOSED_CONNECTION,
	CONNECTOR_ERROR_TCP_ERROR,
	CONNECTOR_ERROR_CANNOT_CONNECT,
	CONNECTOR_ERROR_SENDING,
	// So on...
};
/*
 * those states are with respect to SQL
 * not with respect to the Raw API
 *
 */
enum state {
	CONNECTOR_STATE_IDLE,
	CONNECTOR_STATE_CONNECTING,
	CONNECTOR_STATE_SENDING,
	CONNECTOR_STATE_SENDING_DONE,
	CONNECTOR_STATE_CONNECTOR_ERROR
};

#define MAX_FIELDS    0x20   // Maximum number of fields. Reduce to save memory. Default=32

// Structure for retrieving a field (minimal implementation).
typedef struct {
  char *db;
  char *table;
  char *name;
} field_struct;

// Structure for storing result set metadata.
typedef struct {
  u16_t num_fields;     // actual number of fields
  field_struct *fields[MAX_FIELDS];
} column_names;

// Structure for storing row data.
typedef struct {
  char *values[MAX_FIELDS];
} row_values;

typedef u16_t sqlc_descriptor;
#define MAX_SQL_CONNECTORS 10

u16_t sqlc_create( sqlc_descriptor* d );
u16_t sqlc_connect(sqlc_descriptor* d ,const char* hostname ,u16_t port, const char* username ,const char* password );
u16_t sqlc_disconnect(sqlc_descriptor*d);
u16_t sqlc_delete(sqlc_descriptor*d);
u16_t sqlc_get_state(sqlc_descriptor*d,enum state* state);
u16_t sqlc_get_error_state(sqlc_descriptor*d,enum error_state* es);
u16_t sqlc_is_connected(sqlc_descriptor*d, char* connected);
u16_t sqlc_execute(sqlc_descriptor*d,const char* query);


column_names* mysqlc_get_columns(sqlc_descriptor* d);
row_values* mysqlc_get_next_row(sqlc_descriptor* d);

#endif /* INC_SQL_CONNECTOR_H_ */
