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

///@{
/** 
 * mySQL packet types. \n
 *            MYSQL_OK_PACKET   : mySQL OK packet.\n
 *            MYSQL_EOF_PACKET  : mySQL END OF FRAME Packet.\n
 *            MYSQL_ERROR_PACKET: mySQL ERROR packet.\n
*/
#define MYSQL_OK_PACKET     0x00
#define MYSQL_EOF_PACKET    0xfe
#define MYSQL_ERROR_PACKET  0xff
///@}


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

/**
 * when mySQL Connector state is CONNECTOR_STATE_CONNECTOR_ERROR.\n
 * this enum show's the type of ERROR happenned.\n
 * Default is CONNECTOR_ERROR_OK.\n
 * 
*/

enum error_state {
  /** No error. */
	CONNECTOR_ERROR_OK,
  /** Attempt to send packets\n
 * on a none connected mySQL Connector.*/
	CONNECTOR_ERROR_NOT_CONNECTED,
  /** the Connection with the server is closed non gracefully. */
	CONNECTOR_ERROR_UNEXPECTED_CLOSED_CONNECTION,
  /** internal LWIP Stack error. */
	CONNECTOR_ERROR_TCP_ERROR,
  /** cannot connect to the server.*/
	CONNECTOR_ERROR_CANNOT_CONNECT,
  /** error while trying to send data to the server ( connection were successful ).*/
	CONNECTOR_ERROR_SENDING,
};

/**
 * mySQL Connector (client) states\n
 * 
 * @note those states are with respect to mySQL
 * not the Raw API's
 *
 */
enum state {
  /** MySQL Connector is IDLE, is not trying to connect or send data to a server.*/
	CONNECTOR_STATE_IDLE,
  /** MySQL Connector is trying to connect to a server.*/
	CONNECTOR_STATE_CONNECTING,
  /** MySQL Connector is trying to send data to a server.*/
	CONNECTOR_STATE_SENDING,
  /** MySQL Connector sent data to the server.*/
	CONNECTOR_STATE_SENDING_DONE,
  /** MySQL connector has an error while a session attempt, check the connector error state to know the type of error.*/
	CONNECTOR_STATE_CONNECTOR_ERROR
};
/** 
 * Maximum number of mySQL fields(columns).\n
 *  Reduce to save memory.\n
 *  Default=32. 
 * 
 * @warning it's expected the client knows the max number of columns on the table it tries to retrieve. and the client attempts will fail if it tried to retriev bigger tables.
 */
#define MAX_FIELDS    0x20

/** 
 * Structure for retrieving a mySQL table field (minimal implementation).\n
 */
typedef struct {
  /** pointer to database name string in the MYSQL Frame. */
  char *db;
  /** pointer to database table name string in the MYSQL Frame. */
  char *table;
  /** pointer to field (column) name. */
  char *name;
} field_struct;

/**
 *  Structure for storing mySQL Query result set metadata.\n
 *
 **/
typedef struct {
  /** actual number of fields.*/
  u16_t num_fields;
  /** array of pointers to each field(column) structure, note that max number of fields is fixed,to save memory and help working on small memory controllers.*/
  field_struct *fields[MAX_FIELDS];
} column_names;

/** 
 * Structure for storing each row data in a mySQL table.\n
 */
typedef struct {
  /** Pointer a array of row value strings, limited by MAX_FIELDS obviously.*/
  char *values[MAX_FIELDS];
} row_values;

/**
 *  This implementation for LWIP MySQL connector follows a sockets like 
 *  convention, each connector has it's own
 *  descriptor which is an integer representing an ID for the connector and the 
 *  user application can track it's connector
 *  status and send commands using this descriptor (ID).
 **/
typedef u16_t sqlc_descriptor;

/** limits number of simultanous connections made by the application. */
#define MAX_SQL_CONNECTORS 10

u16_t sqlc_create( sqlc_descriptor* d );
u16_t sqlc_connect(sqlc_descriptor* d ,const char* hostname ,u16_t port, const char* username ,const char* password );
u16_t sqlc_disconnect(sqlc_descriptor*d);
u16_t sqlc_delete(sqlc_descriptor*d);
u16_t sqlc_get_state(sqlc_descriptor*d,enum state* state);
u16_t sqlc_get_error_state(sqlc_descriptor*d,enum error_state* es);
u16_t sqlc_is_connected(sqlc_descriptor*d, char* connected);

/* mySQL related API's */
u16_t sqlc_execute(sqlc_descriptor*d,const char* query);
column_names* mysqlc_get_columns(sqlc_descriptor* d);
row_values* mysqlc_get_next_row(sqlc_descriptor* d);

#endif /* INC_SQL_CONNECTOR_H_ */