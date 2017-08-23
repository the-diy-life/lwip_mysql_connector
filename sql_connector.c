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
#include "lwip/snmp.h"

#include "lwip/api.h"
#include "lwip/sys.h"
#include "sql_connector.h"
#include <string.h>

/* HTTP methods Strings*/
#define GET_METHOD "GET"
#define POST_METHOD "POST"

const char* get_str = GET_METHOD;
const char* post_str = POST_METHOD;


#define SQLC_POLL_INTERVAL 4   //  4 * 0.5 SEC.
#define SQLC_TIMEOUT 5// * 60 * (sqlc_poll_INTERVAL / 2) // two minutes.

/** Maximum length reserved for server name */
#ifndef SQLC_MAX_SERVERNAME_LEN
#define SQLC_MAX_SERVERNAME_LEN 256
#endif
#define HTTP_MAX_REQUEST_LENGTH 1024
#ifndef SQLC_DEFAULT_PORT
#define SQLC_DEFAULT_PORT 80
#endif
#ifdef SQLC_DEBUG
#undef SQLCC_DEBUG
#endif
#define SQLC_DEBUG         LWIP_DBG_ON

enum sqlc_session_state{
	SQLC_NEW,
	SQLC_CONNECTED,
	SQLC_RECV,
	SQLC_SENT,
	SQLC_CLOSED
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
    unsigned int  timer;
    struct tcp_pcb *pcb;
    struct pbuf* p;

};
struct sql_cd{
	sqlc_descriptor* sqlc_d;
	struct sql_connector* sqlc;
};
static struct sql_cd sqlcd_array[MAX_SQL_CONNECTORS];

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
 * hostname  username , password , need to be permenant in memor as long as we
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

//#endif

/** struct keeping the body and state of an HTTP Client session */
struct sqlc_session {
  /** keeping the state of the HTTP Client session */
  enum sqlc_session_state state;
  /** timeout handling, if this reaches 0, the connection is closed */
  u16_t timer;
  struct tcp_pcb *pcb;
  struct pbuf* p;

  /** target website */
//	struct ip_addr remote_ipaddr;
	ip_addr_t remote_ipaddr;
	/**  requested URL   */
  const char* requestedURL;
  /** size of the requested URL */
  u16_t requestedURL_len;
  /** this is the body of the request to be sent */
  char* request;
  /** this is the length of the body to be sent */
  u16_t request_len;
  /** amount of data from body already sent */
  u16_t request_sent;
	/** callback function to call when closed */
  httpc_result_fn callback_fn;
  /** argument for callback function */
  void *callback_arg;
	/**user stack pointer for storage*/
  struct user_stack* user_stack;
};
/** IP address or DNS name of the server to use for next HTTP request */
static char sqlc_server[SQLC_MAX_SERVERNAME_LEN + 1];
/** TCP port of the server to use for next HTTP request */
static u16_t sqlc_server_port = SQLC_DEFAULT_PORT;

static void
httpc_close(struct httpc_session *s,u8_t result);//, err_t err);
err_t httpc_sent(void *arg, struct tcp_pcb *pcb, u16_t len);
void sqlc_err(void *arg, err_t err);
err_t sqlc_connected(void *arg, struct tcp_pcb *pcb, err_t err);
err_t sqlc_poll(void *arg, struct tcp_pcb *pcb);
err_t sqlc_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pbuf, err_t err);
static void sqlc_cleanup(struct sql_connector *s);

err_t httpc_send_request(struct tcp_pcb *pcb,char* request);
static void
httpc_free(struct httpc_session *s,u8_t result);//, err_t err);

#if LWIP_DNS
/** DNS callback
 * If ipaddr is non-NULL, resolving succeeded, otherwise it failed.
 */
static void
httpc_dns_found(const char* hostname,const ip_addr_t *ipaddr, void *arg)
{
	struct httpc_session *s = arg;
	struct tcp_pcb *pcb = s->pcb;
  err_t err;
  u8_t result;

  LWIP_UNUSED_ARG(hostname);
	LWIP_DEBUGF(HTTPC_DEBUG, ("httpc_dns_found\r\n"));
  if (ipaddr != NULL) {
    LWIP_DEBUGF(HTTPC_DEBUG, ("httpc_dns_found: hostname resolved, connecting\n"));
    err = tcp_connect(pcb, ipaddr, http_server_port, sqlc_connected);
    if (err == ERR_OK) {
      return;
    }
    LWIP_DEBUGF(HTTPC_DEBUG, ("tcp_connect failed: %d\n\r", (int)err));
		result = HTTPC_TCP_MEM_ERR;
  } else {
    LWIP_DEBUGF(HTTPC_DEBUG, ("HTTP_dns_found: failed to resolve hostname: %s\r\n",
      hostname));
		result = HTTPC_RESULT_ERR_HOSTNAME;
    //err = ERR_ARG;
  }
  httpc_close(pcb->callback_arg,result);//,err);
}
#endif
/** Set IP address or DNS name for next HTTP connection
 *
 * @param server IP address (in ASCII representation) or DNS name of the server
 */
void
httpc_set_server_addr(const char* server)
{
  size_t len = 0;
  if (server != NULL) {
    len = strlen(server);
  }
  if (len > HTTP_MAX_SERVERNAME_LEN) {
    len = HTTP_MAX_SERVERNAME_LEN;
  }
  memcpy(http_server, server, len);
}



/*
 * Comment of the SMTP client.
 * Same as SMTP_send_mail, but doesn't copy from, to, subject and body into
 * an internal buffer to save memory.
 * WARNING: the above data must stay untouched until the callback function is
 *          called (unless the function returns != ERR_OK)
 */
err_t sql_connector_connect_static(const char* address,
		unsigned int port, const char* username,const char* password)
{
  struct sqlc_session* s;
  size_t len;
	const char* method_ptr ;
  s = mem_malloc(sizeof(struct sqlc_session));
  if (s == NULL) {
	LWIP_DEBUGF(HTTPC_DEBUG,("httpc_sendrequest_static():cannot allocate memory for the state structure , try again later ? \n\r"));
    return ERR_MEM;
  }
  memset(s, 0, sizeof(struct sqlc_session));
  /* initialize the structure */
  s->requestedURL = requestedURL;
  s->callback_fn = callback_fn;
  s->callback_arg = callback_arg;
  s->user_stack = user_stack;
  s->user_stack->top = 0;
  len = strlen(requestedURL);
  LWIP_ASSERT("string is too long", len <= 0xffff);
  s->requestedURL_len = (u16_t)len;
  httpc_set_server_addr(host);
	s->request = (char*)mem_malloc(HTTP_MAX_REQUST_LENGTH);
	if(s->request == NULL){
		LWIP_DEBUGF(HTTPC_DEBUG,("httpc_sendrequest_static():cannot allocate memory for the request \n\r"));
		mem_free(s);
		//httpc_free(s,HTTPC_RESULT_ERR_UNKNOWN,ERR_MEM);
		return ERR_MEM;
	}
	memset(s->request,0,HTTP_MAX_REQUST_LENGTH);
	if(method == GET)
		method_ptr = get_str;
	else if (method == POST)
		method_ptr = post_str;
	sprintf(s->request,"%s %s HTTP/1.1\r\n"\
	"Host: %s:%d\r\n"\
	,method_ptr,s->requestedURL,http_server,http_server_port);
	if(auth)
	{
		char buff[512];
		memset(buff,0,sizeof(buff));
		sprintf(buff,"Authorization: %s\r\nCache-Control: no-cache\r\nConnection: Close\r\n",auth_msg);
		strcat(s->request,buff);
	}
	if(method == POST)
	{
		char buff[100];
		int content_length = strlen(message);
		memset(buff,0,sizeof(buff));
		sprintf(buff,"Content-Type:application/x-www-form-urlencoded \r\n"\
		"Content-Length:%d\r\n\r\n",content_length);
		strcat(s->request,buff);
		strcat(s->request,message);
	}
	else{
		strcat(s->request,"nConnection: Close\r\n\r\n");
	}
//	sprintf(s->request,
//					"GET %s HTTP/1.1\r\n"\
//					"Accept: */*\r\n "\
//					"Accept-Language: zh-cn\r\n"\
//					"User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)\r\n"\
//					"Host: %s:%d\r\n"\
//					"Connection: Close\r\n\r\n",
//					s->requestedURL,http_server,
//					http_server_port);
  LWIP_DEBUGF(HTTPC_DEBUG,("%s", s->request));//准备request，将要发送给主机
  len = strlen(s->request);
  LWIP_ASSERT("string is too long", len <= 0xffff);
  s->request_len = (u16_t)len;
  /* call the actual implementation of this function */
  return httpc_sendrequest_allocated(s);
}

err_t sqlc_connected(void *arg, struct tcp_pcb *pcb, err_t err)
 {
     err_t ret_code = ERR_OK;
     struct sql_connector* sqlc_ptr = arg;
	 LWIP_UNUSED_ARG(err); /* for some compilers warnings. */
	 sqlc_ptr->timer = SQLC_TIMEOUT;
	 tcp_recv(pcb, sqlc_recv);
	 sqlc_ptr->state = SQLC_CONNECTED ;
//	 ret_code = httpc_send_request(pcb,s->request + s->request_sent);
//	 if(ret_code == ERR_OK) {
//		 LWIP_DEBUGF(HTTPC_DEBUG,("sqlc_connected():Request Sent \n\r"));
//	 }
//	 else {
//		 LWIP_DEBUGF(HTTPC_DEBUG,("sqlc_connected():Sending Request failed %d \n\r",ret_code));
//		// inform application to wait untill buffer is not busy  ?
//		// tcp_close(pcb);
//		 ret_code = ERR_ABRT;
//		 httpc_close(s,HTTPC_TCP_MEM_ERR);//,ERR_MEM);
//	 }
	 return ret_code; // ??
}
//still...
void sqlc_err(void *arg, err_t err)
 {
	 struct sql_connector *s = arg;
	 LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_err():error at client : %d\n\r",err));
	 if(s->connector_state == CONNECTOR_STATE_CONNECTING  && s->state == SQLC_CONNECTED){
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
		if(s->connector_state == CONNECTOR_STATE_CONNECTING && s->state == SQLC_NEW){
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
		}
		// TODO handle other events..
		if(s->state == SQLC_SENT && s->request_sent != s->request_len){
			LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_poll: continue sending the request\n\r"));
			err = httpc_send_request(pcb,s->request+s->request_sent);
			if(err!= ERR_OK){
				 LWIP_DEBUGF(SQLC_DEBUG,("sqlc_poll():Sending Request failed %d \n\r",ret_code));
				 ret_code = ERR_ABRT;
				 httpc_close(s,HTTPC_TCP_MEM_ERR);//,ERR_MEM);
			}
		}
	}
	else{
		LWIP_DEBUGF(HTTPC_DEBUG, ("sqlc_poll: something wrong\n\r"));
	}
 return ret_code;
 }
static void
sqlc_cleanup(struct sql_connector *s)
{
	LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_cleanup()\r\n"));
	if(s->pcb)
		/* try to clean up the pcb if not already deallocated*/
		sqlc_close(s);
}
 /** Frees the smpt_session and calls the callback function */
static void
httpc_free(struct httpc_session *s,u8_t result)//, err_t err)
{
	httpc_result_fn fn = s->callback_fn;
	void *arg = s->callback_arg;
	LWIP_DEBUGF(HTTPC_DEBUG, ("httpc_free()\r\n"));
  if (s->p != NULL) {
    pbuf_free(s->p);
  }
	if(s->request !=NULL){
		mem_free(s->request);
	}
  mem_free(s);
	if (fn != NULL) {
    fn(arg, result);//, err);
  }
}
/** Try to close a pcb and free the arg if successful */
static int
sqlc_close(struct sql_connector *s)//, err_t err)
{
	LWIP_DEBUGF(HTTPC_DEBUG, ("sqlc_close()\r\n"));
	tcp_arg(s->pcb, NULL);
	tcp_poll(s->pcb,NULL,0);  // may be wrong ?
	tcp_sent(s->pcb, NULL);
	tcp_recv(s->pcb, NULL);
	tcp_err(s->pcb, NULL);
	tcp_connect(s->pcb,NULL,0,NULL);
	if (tcp_close(s->pcb) == ERR_OK) {
	  return 0 ;
	}
	/* close failed, set back arg */
	tcp_arg(s->pcb, s);
	sqlc_cleanup(s);
	return 1;
}
/** Try to close a pcb and free the arg if successful */
static void
httpc_close(struct httpc_session *s,u8_t result)//, err_t err)
{
	LWIP_DEBUGF(HTTPC_DEBUG, ("httpc_close()\r\n"));
  tcp_arg(s->pcb, NULL);
  tcp_poll(s->pcb,NULL,0);  // may be wrong ?
  tcp_sent(s->pcb, NULL);
  tcp_recv(s->pcb, NULL);
  tcp_err(s->pcb, NULL);
  tcp_connect(s->pcb,NULL,0,NULL);
	if(  result == HTTPC_BUFFER_ERR /* test it by small buffers*/
		/*|| result == HTTPC_RESULT_ERR_CONNECT */
	  /*|| result == HTTPC_RESULT_ERR_UNKNOWN */ /* will never happen */
	  || result == HTTPC_RESULT_ERR_TIMEOUT
	  || result == HTTPC_TCP_MEM_ERR){
			tcp_abort(s->pcb);
			if (s != NULL) {
				httpc_free(s,result);//,err);
			}
	}
  else if (tcp_close(s->pcb) == ERR_OK) {
    if (s != NULL) {
      httpc_free(s,result);//,err);
    }
  } else {
    /* close failed, set back arg */
    tcp_arg(s->pcb, s);
  }
}
char seed[20];
char* server_version = NULL;
void parse_handshake_packet(struct pbuf *p)
{
	int len = strlen(p->payload[5]);
	server_version = mem_malloc(len);
	if(server_version)
		strcpy(server_version,p->payload[5]);
	int seed_index = len + 6 ;
	for(int i = 0 ; i < 8 ; i++)
		seed[i] = p->payload[seed_index + i ];
	seed_index += 27 ;
	for(int i = 0 ; i < 12 ; i++)
	{
		seed[i + 8] = p->payload[seed_index + i ];
	}
}
err_t sqlc_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
     err_t ret_code = ERR_OK;
     struct sql_connector* s = arg;
	 LWIP_UNUSED_ARG(err);
//	 s->timer = SQLC_TIMEOUT;
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
		 if(s->connector_state == CONNECTOR_STATE_CONNECTING){
			 if(p->tot_len > 4){
				 unsigned long packet_length = p->payload[0];
				 packet_length += p->payload[1]<<8;
				 packet_length += p->payload[2]<<16;
				 if(p->tot_len >= packet_length + 4){
					 parse_handshake_packet(p);
					 tcp_recved(pcb, p->tot_len);
				     pbuf_free(p);
				 }
			 }


		 }
		 //LWIP_DEBUGF(HTTPC_DEBUG,("sqlc_recv():The following is the response header:\n"));
		 if((s->user_stack->top + s->p->tot_len)< MAX_STACK_SIZE){
			 for (q = s->p; q != NULL; q = q->next) {
				 for(i=0;i<q->len ;i++){
					 s->user_stack->items[s->user_stack->top]=((char *)(q->payload))[i];
					 s->user_stack->top++;
				 }
			 }
			 tcp_recved(pcb, p->tot_len);
		     pbuf_free(p);
	   }
	   else{
			  LWIP_DEBUGF(HTTPC_DEBUG,("sqlc_recv():your stack size is not enough\r\n"));
				ret_code = ERR_ABRT; // or ERR_MEM and recieve later ?? in this case don't close.
				httpc_close(s,HTTPC_BUFFER_ERR);//,ERR_BUF);
		 }
	 }
	 else{
		 LWIP_DEBUGF(SQLC_DEBUG, ("sqlc_recv: connection closed by remote host\n\r"));
		 if(s->connector_state == CONNECTOR_STATE_CONNECTING  && s->state == SQLC_CONNECTED){
			 s->connector_state  =  CONNECTOR_STATE_CONNECTOR_ERROR ;
			 s->es = CONNECTOR_ERROR_UNEXPECTED_CLOSED_CONNECTION;
		 }
		 sqlc_close(s);
		 s->state = SQLC_CLOSED;
	 }

	 return ret_code;
}
err_t httpc_send_request(struct tcp_pcb *pcb,char* request){
	int len ;
  err_t ret_code = ERR_OK,err;
  len=strlen(request);
	if(len > tcp_sndbuf(pcb)){
		LWIP_DEBUGF(HTTPC_DEBUG,("httpc_send_request: request lenght is Larger than max amount%d\n\r",err));
		len = tcp_sndbuf(pcb);
	}
	LWIP_DEBUGF(HTTPC_DEBUG, ("httpc_send_request: TCP write: %d\r\n",len));
		 err =  tcp_write(pcb, request, len, 0);
		 if (err != ERR_OK) {
				LWIP_DEBUGF(HTTPC_DEBUG,("httpc_send_request: error writing! %d\n\r",err));
				ret_code = err ;
			  return ret_code;
		 }
		 tcp_sent(pcb, httpc_sent);
     return ret_code;
}
err_t httpc_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
	struct httpc_session* s = arg;
	LWIP_DEBUGF(HTTPC_DEBUG,("httpc_sent:Done Sending to client : %d",len));
  LWIP_DEBUGF(HTTPC_DEBUG,("\n\r"));
	s->state = SQLC_SENT;
	s->request_sent += len ;
  return ERR_OK;
}

