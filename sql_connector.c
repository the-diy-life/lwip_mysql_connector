/*
 sql_connector.c
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

#include "lwip/tcp.h"
#include "lwip/raw.h"

#include "lwip/opt.h"
#include "lwip/dns.h"  // DNS
#include "lwip/def.h"
#include "lwip/memp.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/raw.h"

#include "lwip/stats.h"

#include "arch/perf.h"
#include "arch/cc.h"
#include "lwip/snmp.h"

#include "lwip/api.h"
#include "lwip/sys.h"
#include "sql_connector.h"
#include <string.h>


#define SQLC_POLL_INTERVAL 4   //  4 * 0.5 SEC.
#define SQLC_TIMEOUT 4// * 60 * (sqlc_poll_INTERVAL / 2) // two minutes.

#define HTTP_MAX_REQUEST_LENGTH 1024
#ifndef SQLC_DEFAULT_PORT
#define SQLC_DEFAULT_PORT 3306
#endif
#ifdef SQLC_DEBUG
#undef SQLCC_DEBUG
#endif
#define SQLC_DEBUG         LWIP_DBG_ON


enum sqlc_session_state{
	SQLC_NEW = 0,
	SQLC_CONNECTED,
	SQLC_RECV,
	SQLC_SENT,
	SQLC_CLOSED
};
#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

#define MYSQL_SHA1_K0 0x5a827999
#define MYSQL_SHA1_K20 0x6ed9eba1
#define MYSQL_SHA1_K40 0x8f1bbcdc
#define MYSQL_SHA1_K60 0xca62c1d6

union _sha1_buffer {
  u8_t b[BLOCK_LENGTH];
  u32_t w[BLOCK_LENGTH/4];
};
union _sha1_state {
  u8_t b[HASH_LENGTH];
  u32_t w[HASH_LENGTH/4];
};

const u8_t sha1InitState[] = {
  0x01,0x23,0x45,0x67, // H0
  0x89,0xab,0xcd,0xef, // H1
  0xfe,0xdc,0xba,0x98, // H2
  0x76,0x54,0x32,0x10, // H3
  0xf0,0xe1,0xd2,0xc3  // H4
};
struct sql_connector{
	char connected;
	enum error_state es;
	enum state connector_state;
	/** keeping the state of the SQL Client session */
	enum sqlc_session_state state;
	const char* hostname;
	const char* username;
	const char* password;
	u16_t port;
	ip_addr_t remote_ipaddr;
	  /** timeout handling, if this reaches 0, the connection is closed */
    u16_t  timer;
    struct tcp_pcb *pcb;
    struct pbuf* p;
    u16_t p_index;
    /** this is the body of the payload to be sent */
    char* payload;
    /** this is the length of the body to be sent */
    u16_t payload_len;
    /** amount of data from body already sent */
    u16_t payload_sent;
    char* server_version;

    union _sha1_buffer sha1_buffer;
    u8_t bufferOffset;
    union _sha1_state sha1_state;
    u32_t byteCount;
    u8_t keyBuffer[BLOCK_LENGTH];
    u8_t innerHash[HASH_LENGTH];
    char seed[20];

    u16_t num_cols;
    column_names columns;
    row_values row;
    char columns_read;
};
struct sql_cd{
	sqlc_descriptor* sqlc_d;
	struct sql_connector* sqlc;
};
static struct sql_cd sqlcd_array[MAX_SQL_CONNECTORS];

err_t sqlc_sent(void *arg, struct tcp_pcb *pcb, u16_t len);
void sqlc_err(void *arg, err_t err);
err_t sqlc_connected(void *arg, struct tcp_pcb *pcb, err_t err);
err_t sqlc_poll(void *arg, struct tcp_pcb *pcb);
err_t sqlc_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pbuf, err_t err);
static void sqlc_cleanup(struct sql_connector *s);
static u16_t
sqlc_close(struct sql_connector *s);

err_t sqlc_send(struct tcp_pcb *pcb,struct sql_connector* s);
void store_int(char *buff, u32_t value, u16_t size);
u16_t get_lcb_len(char* buffer,u16_t offset);
u16_t read_int(char* buffer,u16_t offset, u16_t size);
/*
  mysqlc_read_string - Retrieve a string from the buffer

  This reads a string from the buffer. It reads the length of the string
  as the first byte.

  offset[in]      offset from start of buffer

  Returns string - String from the buffer
*/
char * mysqlc_read_string(struct sql_connector* s,u16_t *offset) {
  u16_t len_bytes = get_lcb_len(&((char*)(s->p->payload))[s->p_index] ,((char*)(s->p->payload))[s->p_index + *offset]);
  u16_t len = read_int(&((char*)(s->p->payload))[s->p_index],*offset, len_bytes);
  char *str = (char *)mem_malloc(len+1);
  strncpy(str, &((char*)(s->p->payload))[s->p_index + *offset + len_bytes], len);
  str[len] = 0x00;
  *offset += len_bytes+len;
  return str;
}
/*
 * this function is just moving the pointer to the next packet...
 *
 *
 */
u16_t mysqlc_read_packet(struct sql_connector* s){
	if(s->p->payload){
		//u16_t length  = read_int(s->p->payload,s->p_index, 3);
		 u16_t length = ((char*)s->p->payload)[s->p_index];
		 length += ((char*)s->p->payload)[s->p_index+1]<<8;
		 length += ((char*)s->p->payload)[s->p_index+2]<<16;
		if(length + 4 < s->p->tot_len){
			s->p_index+= length + 4;
			struct pbuf* q = pbuf_skip(s->p,s->p_index,&s->p_index);
			if(s->p!=q){
				struct pbuf* qp1 = s->p,*qp2 = NULL;
				while(qp1->next != q){
					qp2 = qp1;
					qp1 = qp2->next;
				}
				qp1->next = NULL;
				pbuf_free(s->p);
				s->p = q;
			}
			return 0 ;
		}
		return 1 ;
	}
	return 1 ;
}
/*
  mysqlc_free_columns_buffer - Free memory allocated for column names

  This method frees the memory allocated during the get_columns()
  method.

  NOTICE: Failing to call this method after calling get_columns()
          and consuming the column names, types, etc. will result
          in a memory leak. The size of the leak will depend on
          the size of the combined column names (bytes).
*/
void mysqlc_free_columns_buffer(struct sql_connector* s) {
  // clear the columns
  for (u16_t f = 0; f < MAX_FIELDS; f++) {
    if (s->columns.fields[f] != NULL) {
      mem_free(s->columns.fields[f]->db);
      mem_free(s->columns.fields[f]->table);
      mem_free(s->columns.fields[f]->name);
      mem_free(s->columns.fields[f]);
    }
    s->columns.fields[f] = NULL;
  }
  s->num_cols = 0;
  s->columns_read = 0;
}


/*
  mysqlc_free_row_buffer - Free memory allocated for row values

  This method frees the memory allocated during the get_next_row()
  method.

  NOTICE: You must call this method at least once after you
          have consumed the values you wish to process. Failing
          to do will result in a memory leak equal to the sum
          of the length of values and one byte for each max cols.
*/
void mysqlc_free_row_buffer(struct sql_connector* s) {
  // clear the row
  for (u16_t f = 0; f < MAX_FIELDS; f++) {
    if (s->row.values[f] != NULL) {
    	mem_free(s->row.values[f]);
    }
    s->row.values[f] = NULL;
  }
}
/*
  mysqlc_get_row - Read a row from the server and store it in the buffer

  This reads a single row and stores it in the buffer. If there are
  no more rows, it returns MYSQL_EOF_PACKET. A row packet is defined as
  follows.

  Bytes                   Name
  -----                   ----
  n (Length Coded String) (column value)
  ...

  Note: each column is store as a length coded string concatenated
        as a single stream

  Returns integer - MYSQL_EOF_PACKET if no more rows, 0 if more rows available
*/
u16_t mysqlc_get_row(struct sql_connector* s) {
  // Read row packets
	u16_t i = 0;
//	while (i < s->num_cols){
	  if(mysqlc_read_packet(s))
		  return MYSQL_EOF_PACKET;
//	  i++;
//	}
//  if (conn->buffer[4] != MYSQL_EOF_PACKET)
  if (((char*)(s->p->payload))[s->p_index + 4] != MYSQL_EOF_PACKET)
    return 0;
  return MYSQL_EOF_PACKET;
}


/*
  mysql_get_row_values - reads the row values from the read buffer

  This method is used to read the row column values
  from the read buffer and store them in the row structure
  in the class.
*/
u16_t mysqlc_get_row_values(struct sql_connector* s) {
  u16_t res = 0;
  u16_t offset = 0;

  // It is an error to try to read rows before columns
  // are read.
  if (!s->columns_read) {
//    conn->show_error(READ_COLS, true);
    return MYSQL_EOF_PACKET;
  }
  // Drop any row data already read
  mysqlc_free_row_buffer(s);

  // Read a row
  res = mysqlc_get_row(s);
  if (res != MYSQL_EOF_PACKET) {
    offset = 4;
    for (u16_t f = 0; f < s->num_cols; f++) {
      s->row.values[f] = mysqlc_read_string(s,&offset);
    }
  }
  return res;
}

/*
  get_field - Read a field from the server

  This method reads a field packet from the server. Field packets are
  defined as:

  Bytes                      Name
  -----                      ----
  n (Length Coded String)    catalog
  n (Length Coded String)    db
  n (Length Coded String)    table
  n (Length Coded String)    org_table
  n (Length Coded String)    name
  n (Length Coded String)    org_name
  1                          (filler)
  2                          charsetnr
  4                          length
  1                          type
  2                          flags
  1                          decimals
  2                          (filler), always 0x00
  n (Length Coded Binary)    default

  Note: the sum of all db, column, and field names must be < 255 in length
*/
u16_t mysqlc_get_field(struct sql_connector* s,field_struct *fs) {
  u16_t len_bytes;
  u16_t len;
  u16_t offset;

  // Read field packets until EOF
  if(mysqlc_read_packet(s) == 0){
	  if (((char*)(s->p->payload))[s->p_index + 4] != MYSQL_EOF_PACKET) {
		// calculate location of db
		len_bytes = get_lcb_len(&((char*)(s->p->payload))[s->p_index],4);
		len = read_int(&((char*)(s->p->payload))[s->p_index],4, len_bytes);
		offset = 4+len_bytes+len;
		fs->db = mysqlc_read_string(s,&offset);
		// get table
		fs->table = mysqlc_read_string(s,&offset);
		// calculate location of name
		len_bytes = get_lcb_len(&((char*)(s->p->payload))[s->p_index],offset);
		len = read_int(&((char*)(s->p->payload))[s->p_index],offset, len_bytes);
		offset += len_bytes+len;
		fs->name = mysqlc_read_string(s,&offset);
		return 0;
	  }
  }
  return MYSQL_EOF_PACKET;
}

/*
  mysqlc_get_fields - reads the fields from the read buffer

  This method is used to read the field names, types, etc.
  from the read buffer and store them in the columns structure
  in the class.
*/
char mysqlc_get_fields(struct sql_connector* s)
{
  u16_t num_fields = 0;
  u16_t res = 0;

  if (s->p->payload== NULL) {
    return 0;
  }
  if(mysqlc_read_packet(s) == 0){ // added
	  num_fields = ((char*)(s->p->payload))[s->p_index + 4];//conn->buffer[4]; // From result header packet
	  s->columns.num_fields = num_fields;
	  s->num_cols = num_fields; // Save this for later use
	  for (u16_t f = 0; f < num_fields; f++) {
		field_struct *field = (field_struct *)mem_malloc(sizeof(field_struct));
		res = mysqlc_get_field(s,field);
		if (res == MYSQL_EOF_PACKET) {
		  //conn->show_error(BAD_MOJO, true);
		  return 0;
		}
		s->columns.fields[f] = field;
	  }
	  mysqlc_read_packet(s); // EOF packet
	  return 1 ;
  }
  return 0;
}

/*
  mysqlc_get_columns - Get a list of the columns (fields)

  This method returns an instance of the column_names structure
  that contains an array of fields.

  Note: you should call free_columns_buffer() after consuming
        the field data to free memory.
*/
column_names* mysqlc_get_columns(sqlc_descriptor* d) {
	u16_t i = 0 ;
	for (i = 0 ; i < MAX_SQL_CONNECTORS; i++)
	{
		if(sqlcd_array[i].sqlc_d == d && sqlcd_array[i].sqlc != NULL)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return NULL ;
	struct sql_connector* s = sqlcd_array[i].sqlc;
	mysqlc_free_columns_buffer(s);
	mysqlc_free_row_buffer(s);
	s->num_cols = 0;
	if (mysqlc_get_fields(s)) {
		s->columns_read = 1;
		return &s->columns;
	}
	else {
		return NULL;
	}
}

/*
  mysqlc_get_next_row - Iterator for reading rows from a result set

  This method returns an instance of a structure (row_values)
  that contains an array of strings representing the row
  values returned from the server.

  The caller can use the values however needed - by first
  converting them to a specific type or as a string.
*/
row_values* mysqlc_get_next_row(sqlc_descriptor* d) {
	u16_t i = 0 ;
	for (i = 0 ; i < MAX_SQL_CONNECTORS; i++)
	{
		if(sqlcd_array[i].sqlc_d == d && sqlcd_array[i].sqlc != NULL)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return NULL ;
	struct sql_connector* s = sqlcd_array[i].sqlc;

  u16_t res = 0;

  mysqlc_free_row_buffer(s);

  // Read the rows
  res = mysqlc_get_row_values(s);
  if (res != MYSQL_EOF_PACKET) {
    return &s->row;
  }
  return NULL;
}


void Encrypt_SHA1_init(struct sql_connector* s) {
  memcpy(s->sha1_state.b,sha1InitState,HASH_LENGTH);
  s->byteCount = 0;
  s->bufferOffset = 0;
}
u32_t Encrypt_SHA1_rol32(u32_t number, uint8_t bits) {
  return ((number << bits) | (number >> (32-bits)));
}
void Encrypt_SHA1_hashBlock(struct sql_connector* s) {
  // SHA1 only for now
  uint8_t i;
  u32_t a,b,c,d,e,t;

  a=s->sha1_state.w[0];
  b=s->sha1_state.w[1];
  c=s->sha1_state.w[2];
  d=s->sha1_state.w[3];
  e=s->sha1_state.w[4];
  for (i=0; i<80; i++) {
    if (i>=16) {
      t = s->sha1_buffer.w[(i+13)&15] ^ s->sha1_buffer.w[(i+8)&15] ^ s->sha1_buffer.w[(i+2)&15] ^ s->sha1_buffer.w[i&15];
      s->sha1_buffer.w[i&15] = Encrypt_SHA1_rol32(t,1);
    }
    if (i<20) {
      t = (d ^ (b & (c ^ d))) + MYSQL_SHA1_K0;
    } else if (i<40) {
      t = (b ^ c ^ d) + MYSQL_SHA1_K20;
    } else if (i<60) {
      t = ((b & c) | (d & (b | c))) + MYSQL_SHA1_K40;
    } else {
      t = (b ^ c ^ d) + MYSQL_SHA1_K60;
    }
    t+=Encrypt_SHA1_rol32(a,5) + e + s->sha1_buffer.w[i&15];
    e=d;
    d=c;
    c=Encrypt_SHA1_rol32(b,30);
    b=a;
    a=t;
  }
  s->sha1_state.w[0] += a;
  s->sha1_state.w[1] += b;
  s->sha1_state.w[2] += c;
  s->sha1_state.w[3] += d;
  s->sha1_state.w[4] += e;
}
void Encrypt_SHA1_addUncounted(struct sql_connector* s,uint8_t data) {
  s->sha1_buffer.b[s->bufferOffset ^ 3] = data;
  s->bufferOffset++;
  if (s->bufferOffset == BLOCK_LENGTH) {
	Encrypt_SHA1_hashBlock(s);
    s->bufferOffset = 0;
  }
}
void Encrypt_SHA1_write(struct sql_connector* s,uint8_t data) {
  ++s->byteCount;
  Encrypt_SHA1_addUncounted(s,data);
}

void Encrypt_SHA1_write_arr(struct sql_connector* s,const uint8_t* data, u16_t length) {
  for (u16_t i=0; i<length; i++) {
	  Encrypt_SHA1_write(s,data[i]);
  }
}
void Encrypt_SHA1_print(struct sql_connector* s,const uint8_t* data){
	u16_t length = strlen(data);
	Encrypt_SHA1_write_arr(s,data,length);
}
void Encrypt_SHA1_pad(struct sql_connector* s) {
  // Implement SHA-1 padding (fips180-2 ยง5.1.1)

  // Pad with 0x80 followed by 0x00 until the end of the block
  Encrypt_SHA1_addUncounted(s,0x80);
  while (s->bufferOffset != 56) Encrypt_SHA1_addUncounted(s,0x00);

  // Append length in the last 8 bytes
  Encrypt_SHA1_addUncounted(s,0); // We're only using 32 bit lengths
  Encrypt_SHA1_addUncounted(s,0); // But SHA-1 supports 64 bit lengths
  Encrypt_SHA1_addUncounted(s,0); // So zero pad the top bits
  Encrypt_SHA1_addUncounted(s,s->byteCount >> 29); // Shifting to multiply by 8
  Encrypt_SHA1_addUncounted(s,s->byteCount >> 21); // as SHA-1 supports bitstreams as well as
  Encrypt_SHA1_addUncounted(s,s->byteCount >> 13); // byte.
  Encrypt_SHA1_addUncounted(s,s->byteCount >> 5);
  Encrypt_SHA1_addUncounted(s,s->byteCount << 3);
}

uint8_t* Encrypt_SHA1_result(struct sql_connector* s) {
  // Pad to complete the last block
	Encrypt_SHA1_pad(s);

  // Swap byte order back
  for (u16_t i=0; i<5; i++) {
    u32_t a,b;
    a=s->sha1_state.w[i];
    b=a<<24;
    b|=(a<<8) & 0x00ff0000;
    b|=(a>>8) & 0x0000ff00;
    b|=a>>24;
    s->sha1_state.w[i]=b;
  }

  // Return pointer to hash (20 characters)
  return s->sha1_state.b;
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

u16_t sqlc_create( sqlc_descriptor* d ){
	u16_t i = 0 ;
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == d)
			return 1 ;
	}
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == NULL && sqlcd_array[i].sqlc == NULL)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	sqlcd_array[i].sqlc = mem_malloc(sizeof(struct sql_connector));
	if(sqlcd_array[i].sqlc == NULL)
		return 1 ;
	memset(sqlcd_array[i].sqlc,0,sizeof(struct sql_connector));
	sqlcd_array[i].sqlc->connected = 0 ;
	sqlcd_array[i].sqlc->connector_state = CONNECTOR_STATE_IDLE ;
	sqlcd_array[i].sqlc->es = CONNECTOR_ERROR_OK;
	sqlcd_array[i].sqlc_d = d;
	return 0 ;
}
static err_t sqlc_sendrequest_allocated(struct sql_connector* sqlc_ptr)
{
	 struct tcp_pcb *pcb = NULL;
	 err_t ret_code = ERR_OK,err;
	 pcb = tcp_new();
	 if(NULL == pcb)
	 {
		 LWIP_DEBUGF(SQLC_DEBUG, ("httpc_sendrequest_allocated(): calling tcp_new can not allocate memory for PCB.\n\r"));
		 err = ERR_MEM;
		 goto leave;
	 }
	 sqlc_ptr->pcb = pcb;
	 sqlc_ptr->timer = SQLC_TIMEOUT;
	 tcp_arg(pcb, sqlc_ptr);
	 tcp_poll(pcb, sqlc_poll, SQLC_POLL_INTERVAL);
	 tcp_err(pcb, sqlc_err);

	 sqlc_ptr->remote_ipaddr.addr = ipaddr_addr(sqlc_ptr->hostname);
	 err = sqlc_ptr->remote_ipaddr.addr == IPADDR_NONE ? ERR_ARG : ERR_OK;
	 if(err == ERR_OK){
		 ret_code = tcp_connect(pcb, &sqlc_ptr->remote_ipaddr, sqlc_ptr->port, sqlc_connected);
		 if(ERR_OK != ret_code)
		 {
				 LWIP_DEBUGF(SQLC_DEBUG, ("tcp_connect():no memory is available for enqueueing the SYN segment %d\n\r",ret_code));
				 goto deallocate_and_leave;
		 }
	   } else if (err != ERR_INPROGRESS) {
		LWIP_DEBUGF(SQLC_DEBUG, ("dns_gethostbyname failed: %d\r\n", (u16_t)err));
		goto deallocate_and_leave;
	  }

  return ERR_OK;
deallocate_and_leave:
  if (pcb != NULL) {
    tcp_arg(pcb, NULL);
    tcp_close(pcb);
  }
leave:
//  mem_free(sqlc_ptr);
  /* no need to call the callback here since we return != ERR_OK */
  return err;
}
/*
 * hostname  username , password , need to be permenant in memory as u32_t as we
 * have the connector..
 *
 *
 */
u16_t sqlc_connect(sqlc_descriptor* d ,const char* hostname ,u16_t port, const char* username ,const char* password )
{
	u16_t i = 0 ;
	for (i = 0 ; i < MAX_SQL_CONNECTORS; i++)
	{
		if(sqlcd_array[i].sqlc_d == d && sqlcd_array[i].sqlc != NULL)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	struct sql_connector* sqlc_ptr = sqlcd_array[i].sqlc;
	if(sqlc_ptr->connected)
		return 1 ;
	sqlc_ptr->hostname = hostname;
	sqlc_ptr->username = username;
	sqlc_ptr->password = password;
	sqlc_ptr->port = port;

	err_t err = sqlc_sendrequest_allocated(sqlc_ptr);
	if(err != ERR_OK)
		return 1;
	sqlc_ptr->connector_state = CONNECTOR_STATE_CONNECTING;
	sqlc_ptr->es = CONNECTOR_ERROR_OK;
	return 0 ;
}
u16_t sqlc_disconnect(sqlc_descriptor*d)
{
	u16_t i = 0 ;
	for (i = 0 ; i < MAX_SQL_CONNECTORS; i++)
	{
		if(sqlcd_array[i].sqlc_d == d && sqlcd_array[i].sqlc != NULL)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	/* Don't disconnect a busy connector */
	if(sqlcd_array[i].sqlc->connector_state != CONNECTOR_STATE_IDLE){
		return 1 ;
	}
	if(sqlc_close(sqlcd_array[i].sqlc))
		return 1 ;
	if(sqlcd_array[i].sqlc->connected){
		sqlcd_array[i].sqlc->connected = 0 ;
		sqlcd_array[i].sqlc->connector_state = CONNECTOR_STATE_IDLE ;
		sqlcd_array[i].sqlc->es = CONNECTOR_ERROR_OK;
		sqlcd_array[i].sqlc->hostname = NULL;
		sqlcd_array[i].sqlc->port = SQLC_DEFAULT_PORT;
		sqlcd_array[i].sqlc->username = NULL;
		sqlcd_array[i].sqlc->password = NULL;
		return 0 ;
	}
	return 1 ;
}
/*
 * you can't delete a connected or not IDLE connector
 * */

u16_t sqlc_delete(sqlc_descriptor*d)
{
	u16_t i = 0 ;
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == d)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	if(sqlcd_array[i].sqlc->connected || sqlcd_array[i].sqlc->connector_state != CONNECTOR_STATE_IDLE)
		return 1 ;
	mem_free(sqlcd_array[i].sqlc);
	sqlcd_array[i].sqlc = NULL;
	sqlcd_array[i].sqlc_d = NULL;
	return 0 ;
}
u16_t sqlc_get_state(sqlc_descriptor*d,enum state* state)
{
	u16_t i ;
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == d)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	*state = sqlcd_array[i].sqlc->connector_state;
	return 0 ;
}
u16_t sqlc_get_error_state(sqlc_descriptor*d,enum error_state* es)
{
	u16_t i ;
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == d)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	*es = sqlcd_array[i].sqlc->es;
	return 0 ;
}
u16_t sqlc_is_connected(sqlc_descriptor*d, char* connected)
{
	u16_t i ;
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == d)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	*connected = sqlcd_array[i].sqlc->connected;
	return 0 ;
}
u16_t sqlc_execute(sqlc_descriptor*d,const char* query){
	u16_t i ;
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == d)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	struct sql_connector* s = sqlcd_array[i].sqlc;

	if(!s->connected)
		return 1 ;
	if(s->connector_state != CONNECTOR_STATE_IDLE && s->connector_state != CONNECTOR_STATE_CONNECTOR_ERROR)
		return 1;
	if(s->p){
		pbuf_free(s->p);
		s->p = NULL;
		s->p_index = 0 ;
	}
	u16_t query_len = strlen(query);
	s->payload  = (char*) mem_malloc( query_len + 5 );
	if(!s->payload)
		return 1 ;
	mysqlc_free_columns_buffer(s);
	mysqlc_free_row_buffer(s);
	memcpy(&s->payload[5], query,query_len);
	store_int(&s->payload[0], query_len+1, 3);
	s->payload[3] = 0x00;
	s->payload[4] = 0x03;  // command packet
	s->payload_len = query_len + 5;
	if(sqlc_send(s->pcb,s) != ERR_OK)
		return 1;
	s->connector_state = CONNECTOR_STATE_SENDING;
	s->es = CONNECTOR_ERROR_OK;
	return 0;
}

err_t sqlc_connected(void *arg, struct tcp_pcb *pcb, err_t err)
 {
     err_t ret_code = ERR_OK;
     struct sql_connector* sqlc_ptr = arg;
	 LWIP_UNUSED_ARG(err); /* for some compilers warnings. */
	 sqlc_ptr->timer = SQLC_TIMEOUT;
	 tcp_recv(pcb, sqlc_recv);
	 sqlc_ptr->state = SQLC_CONNECTED ;

	 return ret_code;
}
void sqlc_err(void *arg, err_t err)
 {
	 struct sql_connector *s = arg;
	 LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_err():error at client : %d\n\r",err));
	 if(s->connector_state == CONNECTOR_STATE_CONNECTING  && (s->state <= SQLC_SENT)){
		 s->connector_state  =  CONNECTOR_STATE_CONNECTOR_ERROR ;
		 s->es = CONNECTOR_ERROR_TCP_ERROR;
		 s->state = SQLC_CLOSED;
	 }else if (s->connected){
		 s->connected = 0 ;
	 }
	 s->connector_state  =  CONNECTOR_STATE_CONNECTOR_ERROR ;
	 s->es = CONNECTOR_ERROR_TCP_ERROR;
	 s->state = SQLC_CLOSED;
	 //@ TODO handle other events , basically we check the connector state and the session state...
	 sqlc_cleanup(s);

}
err_t sqlc_poll(void *arg, struct tcp_pcb *pcb)
{
    err_t ret_code = ERR_OK,err;
	LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_poll()\r\n"));
	if (arg != NULL) {
		struct sql_connector *s = arg;
		LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_poll(): %d\n\r",s->timer));
		if(s->connector_state == CONNECTOR_STATE_CONNECTING){
			if (s->timer != 0) {
				s->timer--;
			}
			 /* idle timer, close connection if timed out */
			if (s->timer == 0) {
				LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_poll: connection timed out, closing\n\r"));
				sqlc_close(s); // TODO handle it's return...
				s->connector_state = CONNECTOR_STATE_CONNECTOR_ERROR;
				s->es = CONNECTOR_ERROR_CANNOT_CONNECT;
				s->state = SQLC_CLOSED;
				ret_code = ERR_ABRT;
			}
		}else if(s->connector_state == CONNECTOR_STATE_SENDING)
		{
			if (s->timer != 0) {
				s->timer--;
			}

			if (s->timer == 0) {
			      s->connector_state = CONNECTOR_STATE_CONNECTOR_ERROR;
				  s->es = CONNECTOR_ERROR_SENDING;
			}
		}
		// TODO handle other events..
	}
	else{
		LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_poll: something wrong\n\r"));
	}
 return ret_code;
}
static void
sqlc_cleanup(struct sql_connector *s)
{
	LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_cleanup()\r\n"));
	if(s->pcb){
		/* try to clean up the pcb if not already deallocated*/
		//sqlc_close(s);
		s->pcb = NULL;
	}
	if(s->payload){
		mem_free(s->payload);
		s->payload = NULL;
	}
	if(s->server_version){
		mem_free(s->server_version);
		s->server_version = NULL;
	}
	mysqlc_free_columns_buffer(s);
	mysqlc_free_row_buffer(s);
	if(s->p){
		pbuf_free(s->p);
		s->p = NULL;
		s->p_index = 0 ;
	}
}

/** Try to close a pcb and free the arg if successful */
static u16_t
sqlc_close(struct sql_connector *s)
{
	LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_close()\r\n"));
	tcp_arg(s->pcb, NULL);
	tcp_poll(s->pcb,NULL,0);  // may be wrong ?
	tcp_sent(s->pcb, NULL);
	tcp_recv(s->pcb, NULL);
	tcp_err(s->pcb, NULL);
	tcp_connect(s->pcb,NULL,0,NULL);
	if (tcp_close(s->pcb) == ERR_OK) {
		s->connected = 0 ;
		s->pcb = NULL;
		sqlc_cleanup(s);
	  return 0 ;
	}
	/* close failed, set back arg */
	tcp_arg(s->pcb, s);
	s->connected = 0 ;
	sqlc_cleanup(s);
	return 1;
}



void parse_handshake_packet(struct sql_connector* s,struct pbuf *p)
{
	u16_t len = strlen(&(((char*)p->payload)[5]));
	s->server_version = (char*)mem_malloc(len + 1);
	if(s->server_version)
		strcpy(s->server_version,&(((char*)p->payload)[5]));
	u16_t seed_index = len + 6  + 4;
	for(u16_t i = 0 ; i < 8 ; i++)
		s->seed[i] = ((char*)p->payload)[seed_index + i ];
	seed_index += 27 ;
	for(u16_t i = 0 ; i < 12 ; i++)
	{
		s->seed[i + 8] = ((char*)p->payload)[seed_index + i ];
	}
}
err_t sqlc_send(struct tcp_pcb *pcb,struct sql_connector* s){
	u16_t len ;
	err_t ret_code = ERR_OK,err = ERR_OK;
	len=s->payload_len - s->payload_sent;
	if(len > tcp_sndbuf(pcb)){
		LWIP_DEBUGF(SQLC_DEBUG,("sqlc_send: request length is Larger than max amount%d\n\r",err));
		len = tcp_sndbuf(pcb);
	}
	LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_send: TCP write: %d\r\n",len));
	err =  tcp_write(pcb, s->payload, len, 0);
	if (err != ERR_OK) {
		LWIP_DEBUGF(SQLC_DEBUG,("sqlc_send: error writing! %d\n\r",err));
		ret_code = err ;
		return ret_code;
	}
	tcp_sent(pcb, sqlc_sent);
	return ret_code;
}
char scramble_password(struct sql_connector* s,const char* password , char* pwd_hash)
{
	char *digest;
	char hash1[20];
	char hash2[20];
	char hash3[20];
	char pwd_buffer[40];

	  if (strlen(password) == 0)
	    return 0;

	  // hash1
	  Encrypt_SHA1_init(s);
	  Encrypt_SHA1_print(s,password);
	  digest = Encrypt_SHA1_result(s);
	  memcpy(hash1, digest, 20);

	  // hash2
	  Encrypt_SHA1_init(s);
	  Encrypt_SHA1_write_arr(s,hash1, 20);
	  digest = Encrypt_SHA1_result(s);
	  memcpy(hash2, digest, 20);

	  // hash3 of seed + hash2
	  Encrypt_SHA1_init(s);
	  memcpy(pwd_buffer, &s->seed, 20);
	  memcpy(pwd_buffer+20, hash2, 20);
	  Encrypt_SHA1_write_arr(s,pwd_buffer, 40);
	  digest = Encrypt_SHA1_result(s);
	  memcpy(hash3, digest, 20);

	  // XOR for hash4
	  for (u16_t i = 0; i < 20; i++)
	    pwd_hash[i] = hash1[i] ^ hash3[i];

	  return 1;
}
/*
  store_int - Store an integer value into a byte array of size bytes.

  This writes an integer into the buffer at the current position of the
  buffer. It will transform an integer of size to a length coded binary
  form where 1-3 bytes are used to store the value (set by size).

  buff[in]        pointer to location in internal buffer where the
                  integer will be stored
  value[in]       integer value to be stored
  size[in]        number of bytes to use to store the integer
*/
void store_int(char *buff, u32_t value, u16_t size) {
  memset(buff, 0, size);
  if (value < 0xff)
    buff[0] = (char)value;
  else if (value < 0xffff) {
    buff[0] = (char)value;
    buff[1] = (char)(value >> 8);
  } else if (value < 0xffffff) {
    buff[0] = (char)value;
    buff[1] = (char)(value >> 8);
    buff[2] = (char)(value >> 16);
  } else if (value < 0xffffff) {
    buff[0] = (char)value;
    buff[1] = (char)(value >> 8);
    buff[2] = (char)(value >> 16);
    buff[3] = (char)(value >> 24);
  }
}

err_t send_authentication_packet( struct sql_connector* s, struct tcp_pcb *pcb,const char *user,const char *password)
{
	s->payload = (char*) mem_malloc(256);
	if(s){
	  u16_t size_send = 4;
	  err_t err = ERR_OK;
	  // client flags
	  s->payload[size_send] = 0x85;
	  s->payload[size_send+1] = 0xa6;
	  s->payload[size_send+2] = 0x03;
	  s->payload[size_send+3] = 0x00;
	  size_send += 4;

	  // max_allowed_packet
	  s->payload[size_send] = 0;
	  s->payload[size_send+1] = 0;
	  s->payload[size_send+2] = 0;
	  s->payload[size_send+3] = 1;
	  size_send += 4;

	  // charset - default is 8
	  s->payload[size_send] = 0x08;
	  size_send += 1;
	  for(u16_t i = 0; i < 24; i++)
	    s->payload[size_send+i] = 0x00;
	  size_send += 23;

	  // user name
	  memcpy((char *)&s->payload[size_send], user, strlen(user));
	  size_send += strlen(user) + 1;
	  s->payload[size_send-1] = 0x00;

	  // password - see scramble password
	   char scramble[20];
	   if (scramble_password(s,password, scramble)) {
	     s->payload[size_send] = 0x14;
	     size_send += 1;
	     for (u16_t i = 0; i < 20; i++)
	       s->payload[i+size_send] = scramble[i];
	     size_send += 20;
	     s->payload[size_send] = 0x00;
	   }
	   // terminate password response
	   s->payload[size_send] = 0x00;
	   size_send += 1;

	   // database
	   s->payload[size_send+1] = 0x00;
	   size_send += 1;
	   s->payload_len = size_send;
	   // Write packet size
	   u16_t p_size = size_send - 4;
	   store_int(&s->payload[0], p_size, 3);
	   s->payload[3] = 0x01;
	   err = sqlc_send(pcb, s);
	   return err;
	}
	return ERR_MEM;
}
/*
  get_lcb_len - Retrieves the length of a length coded binary value

  This reads the first byte from the offset into the buffer and returns
  the number of bytes (size) that the integer consumes. It is used in
  conjunction with read_int() to read length coded binary integers
  from the buffer.

  Returns integer - number of bytes integer consumes
*/
u16_t get_lcb_len(char* buffer,u16_t offset) {
  u16_t read_len = buffer[offset];
  if (read_len > 250) {
    // read type:
    char type = buffer[offset+1];
    if (type == 0xfc)
      read_len = 2;
    else if (type == 0xfd)
      read_len = 3;
    else if (type == 0xfe)
      read_len = 8;
  }
  return 1;
}

/*
  read_int - Retrieve an integer from the buffer in size bytes.

  This reads an integer from the buffer at offset position indicated for
  the number of bytes specified (size).

  offset[in]      offset from start of buffer
  size[in]        number of bytes to use to store the integer

  Returns integer - integer from the buffer
*/
u16_t read_int(char* buffer,u16_t offset, u16_t size) {
  u16_t value = 0;
  u16_t new_size = 0;
  if (size == 0)
     new_size = get_lcb_len(buffer,offset);
  if (size == 1)
     return buffer[offset];
  new_size = size;
  u16_t shifter = (new_size - 1) * 8;
  for (u16_t i = new_size; i > 0; i--) {
    value += (char)(buffer[i-1] << shifter);
    shifter -= 8;
  }
  return value;
}
/*
  check_ok_packet - Decipher an Ok packet from the server.

  This method attempts to parse an Ok packet. If the packet is not an
  Ok, packet, it returns the packet type.

   Bytes                       Name
   -----                       ----
   1   (Length Coded Binary)   field_count, always = 0
   1-9 (Length Coded Binary)   affected_rows
   1-9 (Length Coded Binary)   insert_id
   2                           server_status
   2                           warning_count
   n   (until end of packet)   message

  Returns integer - 0 = successful parse, packet type if not an Ok packet
*/
u16_t check_ok_packet(char* buffer) {
	if(buffer != NULL){
	  u16_t type = buffer[4];
	  if (type != MYSQL_OK_PACKET)
		return type;
	  return 0;
	}
	return MYSQL_ERROR_PACKET;
}

/*
  parse_error_packet - Display the error returned from the server

  This method parses an error packet from the server and displays the
  error code and text via Serial.print. The error packet is defined
  as follows.

  Note: the error packet is already stored in the buffer since this
        packet is not an expected response.

  Bytes                       Name
  -----                       ----
  1                           field_count, always = 0xff
  2                           errno
  1                           (sqlstate marker), always '#'
  5                           sqlstate (5 characters)
  n                           message
*/
void parse_error_packet(char* buffer,u16_t packet_len) {
  LWIP_DEBUGF(SQLC_DEBUG,("Error: "));
  LWIP_DEBUGF(SQLC_DEBUG,("%d",read_int(buffer,5, 2)));
  LWIP_DEBUGF(SQLC_DEBUG,(" = "));
  for (u16_t i = 0; i < packet_len-9; i++)
	  LWIP_DEBUGF(SQLC_DEBUG,("%c",(char)buffer[i+13]));
  LWIP_DEBUGF(SQLC_DEBUG,("."));
}

err_t
sqlc_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
     err_t ret_code = ERR_OK;
     struct sql_connector* s = arg;
	 LWIP_UNUSED_ARG(err);
	 if(p != NULL)
	 {
		 struct pbuf *q;
		 u16_t i =0;
		 /* received data */
		 if (s->p == NULL) {
				s->p = p;
		 }else {
				pbuf_cat(s->p, p);
		 }
		 if(s->connector_state == CONNECTOR_STATE_CONNECTING && s->state == SQLC_CONNECTED){
			 if(p->tot_len > 4){
				 u32_t packet_length = ((char*)p->payload)[0];
				 packet_length += ((char*)p->payload)[1]<<8;
				 packet_length += ((char*)p->payload)[2]<<16;
				 if(p->tot_len >= packet_length + 4){
					 parse_handshake_packet(s,p);
					 tcp_recved(pcb, p->tot_len);
				     pbuf_free(p);
				     s->p = NULL;
				     err_t err = send_authentication_packet(s,pcb,(const char*)s->username,(const char*)s->password);
				     if(err != ERR_OK){
				    	 s->connector_state = CONNECTOR_STATE_CONNECTOR_ERROR;
				    	 s->es = CONNECTOR_ERROR_CANNOT_CONNECT;
				    	 /* Don't Need to close the connection as the server will already abort it on time out ??*/
				     }else{
						 s->es = CONNECTOR_ERROR_OK;
						 s->timer = SQLC_TIMEOUT;
				     }
				 }
			 }
		 }else if (s->connector_state == CONNECTOR_STATE_CONNECTING && (s->state == SQLC_RECV || s->state == SQLC_SENT)){
			 if(p->tot_len > 4){
				 u32_t packet_length = ((char*)p->payload)[0];
				 packet_length += ((char*)p->payload)[1]<<8;
				 packet_length += ((char*)p->payload)[2]<<16;
				 if(p->tot_len >= packet_length + 4){
					    if (check_ok_packet((char*)p->payload) != 0) {
					      parse_error_packet((char*)p->payload,p->tot_len);
					      // return false; meaning tell the user we don't have the connection , further close it...
					      s->connector_state = CONNECTOR_STATE_CONNECTOR_ERROR;
						  s->es = CONNECTOR_ERROR_CANNOT_CONNECT;
						  sqlc_close(s);
					    }else{
							LWIP_DEBUGF(SQLC_DEBUG, ("Connected to server version %s\n\r",s->server_version));
							mem_free(s->server_version);
							s->server_version = NULL;

							s->timer = SQLC_TIMEOUT;
							// Tell the application the Good news ?
							s->connected = 1 ; // TODO handle error , sent , poll events.. if connected
							s->connector_state = CONNECTOR_STATE_IDLE;
							s->es = CONNECTOR_ERROR_OK;
					    }
						 tcp_recved(pcb, p->tot_len);
					     pbuf_free(p);
					     s->p = NULL;
				 }
			 }
		 }else if (s->connector_state == CONNECTOR_STATE_SENDING){
			 if(p->tot_len > 4){
				 u32_t packet_length = ((char*)p->payload)[0];
				 packet_length += ((char*)p->payload)[1]<<8;
				 packet_length += ((char*)p->payload)[2]<<16;
				 if(p->tot_len >= packet_length + 4){
					    if (check_ok_packet((char*)p->payload) != 0) {
					      parse_error_packet((char*)p->payload,p->tot_len);
					      // return false; meaning tell the user we don't have the connection , further close it...
					      s->connector_state = CONNECTOR_STATE_CONNECTOR_ERROR;
						  s->es = CONNECTOR_ERROR_SENDING;
					    }else{
							LWIP_DEBUGF(SQLC_DEBUG, ("Received \"Ok packet\" after sending Query \n\r"));

							// Tell the application the Good news ?
							s->connector_state = CONNECTOR_STATE_IDLE;
							s->es = CONNECTOR_ERROR_OK;
					    }
						 tcp_recved(pcb, p->tot_len);
//					     pbuf_free(p);
//					     s->p = NULL;
				 }
			 }

		 }else{
			 tcp_recved(pcb, p->tot_len);
		     //pbuf_free(p);
		 }
	     s->state = SQLC_RECV;
	 }
	 else{
		 LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_recv: connection closed by remote host\n\r"));
		 if((s->connector_state == CONNECTOR_STATE_CONNECTING  )
				 && (s->state == SQLC_CONNECTED || s->state == SQLC_RECV || s->state == SQLC_SENT)){
			 s->connector_state  =  CONNECTOR_STATE_CONNECTOR_ERROR ;
			 s->es = CONNECTOR_ERROR_UNEXPECTED_CLOSED_CONNECTION;
		 }
		 sqlc_close(s);
		 s->state = SQLC_CLOSED;
	 }

	 return ret_code;
}
err_t sqlc_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
	struct sql_connector * s = arg;
	LWIP_DEBUGF(SQLC_DEBUG,("sqlc_sent:Done Sending to client : %d",len));
    LWIP_DEBUGF(SQLC_DEBUG,("\n\r"));
    if(s->connector_state == CONNECTOR_STATE_CONNECTING && s->state == SQLC_RECV){

    	s->timer = SQLC_TIMEOUT;
    }else if (s->connector_state == CONNECTOR_STATE_SENDING){
    	s->timer = SQLC_TIMEOUT;
    }
    s->payload_sent +=len;
    if(s->payload && s->payload_len - s->payload_sent)
    {
    	sqlc_send(pcb,s);
    }
    else
    {
    	s->state = SQLC_SENT;

    	if (s->payload && !(s->payload_len - s->payload_sent)){
			mem_free(s->payload);
			s->payload = NULL;
			s->payload_sent = 0;
    	}
    }
  return ERR_OK;
}

