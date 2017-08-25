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
#define SQLC_TIMEOUT 10// * 60 * (sqlc_poll_INTERVAL / 2) // two minutes.

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
  uint8_t b[BLOCK_LENGTH];
  uint32_t w[BLOCK_LENGTH/4];
};
union _sha1_state {
  uint8_t b[HASH_LENGTH];
  uint32_t w[HASH_LENGTH/4];
};

const uint8_t sha1InitState[] = {
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
	int port;
	ip_addr_t remote_ipaddr;
	  /** timeout handling, if this reaches 0, the connection is closed */
    u16_t  timer;
    struct tcp_pcb *pcb;
    struct pbuf* p;
    /** this is the body of the payload to be sent */
    char* payload;
    /** this is the length of the body to be sent */
    u16_t payload_len;
    /** amount of data from body already sent */
    u16_t payload_sent;
    char* server_version;

    union _sha1_buffer sha1_buffer;
    uint8_t bufferOffset;
    union _sha1_state sha1_state;
    uint32_t byteCount;
    uint8_t keyBuffer[BLOCK_LENGTH];
    uint8_t innerHash[HASH_LENGTH];
    char seed[20];
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
static int
sqlc_close(struct sql_connector *s);

err_t sqlc_send(struct tcp_pcb *pcb,struct sql_connector* s);
void store_int(char *buff, long value, int size);
void Encrypt_SHA1_init(struct sql_connector* s) {
  memcpy(s->sha1_state.b,sha1InitState,HASH_LENGTH);
  s->byteCount = 0;
  s->bufferOffset = 0;
}
uint32_t Encrypt_SHA1_rol32(uint32_t number, uint8_t bits) {
  return ((number << bits) | (number >> (32-bits)));
}
void Encrypt_SHA1_hashBlock(struct sql_connector* s) {
  // SHA1 only for now
  uint8_t i;
  uint32_t a,b,c,d,e,t;

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

void Encrypt_SHA1_write_arr(struct sql_connector* s,const uint8_t* data, int length) {
  for (int i=0; i<length; i++) {
	  Encrypt_SHA1_write(s,data[i]);
  }
}
void Encrypt_SHA1_print(struct sql_connector* s,const uint8_t* data){
	int length = strlen(data);
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
  for (int i=0; i<5; i++) {
    uint32_t a,b;
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

int sqlc_create( sqlc_descriptor* d ){
	int i = 0 ;
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
		LWIP_DEBUGF(SQLC_DEBUG, ("dns_gethostbyname failed: %d\r\n", (int)err));
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
 * hostname  username , password , need to be permenant in memory as long as we
 * have the connector..
 *
 *
 */
int sqlc_connect(sqlc_descriptor* d ,const char* hostname ,int port, const char* username ,const char* password )
{
	int i = 0 ;
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
int sqlc_disconnect(sqlc_descriptor*d)
{
	int i = 0 ;
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

int sqlc_delete(sqlc_descriptor*d)
{
	int i = 0 ;
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
int sqlc_get_state(sqlc_descriptor*d,enum state* state)
{
	int i ;
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == d)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	*state = sqlcd_array[i].sqlc->connector_state;
	return 0 ;
}
int sqlc_get_error_state(sqlc_descriptor*d,enum error_state* es)
{
	int i ;
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == d)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	*es = sqlcd_array[i].sqlc->es;
	return 0 ;
}
int sqlc_is_connected(sqlc_descriptor*d, char* connected)
{
	int i ;
	for (i = 0 ; i<MAX_SQL_CONNECTORS ;i++){
		if(sqlcd_array[i].sqlc_d == d)
			break;
	}
	if(i == MAX_SQL_CONNECTORS)
		return 1 ;
	*connected = sqlcd_array[i].sqlc->connected;
	return 0 ;
}
int sqlc_execute(sqlc_descriptor*d,const char* query){
	int i ;
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

	int query_len = strlen(query);
	s->payload  = (char*) mem_malloc( query_len + 5 );
	if(!s->payload)
		return 1 ;
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
		 s->connector_state  =  CONNECTOR_STATE_CONNECTOR_ERROR ;
		 s->es = CONNECTOR_ERROR_TCP_ERROR;
		 s->state = SQLC_CLOSED;
	 }

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
		sqlc_close(s);
	}
	if(s->payload){
		mem_free(s->payload);
		s->payload = NULL;
	}
	if(s->server_version){
		mem_free(s->server_version);
		s->server_version = NULL;
	}
}

/** Try to close a pcb and free the arg if successful */
static int
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
	int len = strlen(&(((char*)p->payload)[5]));
	s->server_version = (char*)mem_malloc(len + 1);
	if(s->server_version)
		strcpy(s->server_version,&(((char*)p->payload)[5]));
	int seed_index = len + 6  + 4;
	for(int i = 0 ; i < 8 ; i++)
		s->seed[i] = ((char*)p->payload)[seed_index + i ];
	seed_index += 27 ;
	for(int i = 0 ; i < 12 ; i++)
	{
		s->seed[i + 8] = ((char*)p->payload)[seed_index + i ];
	}
}
err_t sqlc_send(struct tcp_pcb *pcb,struct sql_connector* s){
	int len ;
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
	  for (int i = 0; i < 20; i++)
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
void store_int(char *buff, long value, int size) {
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
	  int size_send = 4;
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
	  for(int i = 0; i < 24; i++)
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
	     for (int i = 0; i < 20; i++)
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
	   int p_size = size_send - 4;
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
int get_lcb_len(char* buffer,int offset) {
  int read_len = buffer[offset];
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
int read_int(char* buffer,int offset, int size) {
  int value = 0;
  int new_size = 0;
  if (size == 0)
     new_size = get_lcb_len(buffer,offset);
  if (size == 1)
     return buffer[offset];
  new_size = size;
  int shifter = (new_size - 1) * 8;
  for (int i = new_size; i > 0; i--) {
    value += (char)(buffer[i-1] << shifter);
    shifter -= 8;
  }
  return value;
}

int check_ok_packet(char* buffer) {
	if(buffer != NULL){
	  int type = buffer[4];
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
void parse_error_packet(char* buffer,int packet_len) {
  LWIP_DEBUGF(SQLC_DEBUG,("Error: "));
  LWIP_DEBUGF(SQLC_DEBUG,("%d",read_int(buffer,5, 2)));
  LWIP_DEBUGF(SQLC_DEBUG,(" = "));
  for (int i = 0; i < packet_len-9; i++)
	  LWIP_DEBUGF(SQLC_DEBUG,("%c",(char)buffer[i+13]));
  LWIP_DEBUGF(SQLC_DEBUG,("."));
}

err_t sqlc_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
     err_t ret_code = ERR_OK;
     struct sql_connector* s = arg;
	 LWIP_UNUSED_ARG(err);
	 if(p != NULL)
	 {
		 struct pbuf *q;
		 int i =0;
		 /* received data */
		 if (s->p == NULL) {
				s->p = p;
		 }else {
				pbuf_cat(s->p, p);
		 }
		 if(s->connector_state == CONNECTOR_STATE_CONNECTING && s->state == SQLC_CONNECTED){
			 if(p->tot_len > 4){
				 unsigned long packet_length = ((char*)p->payload)[0];
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
				 unsigned long packet_length = ((char*)p->payload)[0];
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
				 unsigned long packet_length = ((char*)p->payload)[0];
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
					     pbuf_free(p);
					     s->p = NULL;
				 }
			 }

		 }else{
			 tcp_recved(pcb, p->tot_len);
		     pbuf_free(p);
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

