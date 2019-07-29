/*
 select.c
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
  Created on: Aug 26, 2017
       Author: Amr Elsayed


       example :
  #include "lwip.h"
  #include "connect.h"

  int main(void)
  {
    MX_LWIP_Init();

    while(1){

     hal_time = HAL_GetTick();
     MX_LWIP_Process(hal_time);
     select_periodic_handler(hal_time);


    }


  }

 */

#include "mysql_connector.h"
#include "./select.h"
#include "lwip/debug.h"


mysqlc_descriptor sd;

// two states (init , loop)
enum connect_states{
  INIT,
  CONNECT,
  CONNECTING,
  CONNECTED
};
enum select_states{
  EXECUTE,
  READ
};
const char hostname[] = "192.168.1.111";
const char username[] = "arduino";
const char password[] = "password";

enum connect_states cs = INIT;
enum select_states ss = EXECUTE;
#define SELECT_PERIOD  10000

u32_t select_time = 0 ;

u16_t dummy = 0;
char read_query[] = "USE powermeter; SELECT * FROM `pm_income` ORDER BY pk_income DESC LIMIT 1;";
void construct_query(char query[]){
  sprintf(query,"use powermeter;"\
  "insert into pm_income "\
  "(controller,meter1, meter2, meter3,meter4, meter5, meter6,meter7, meter8, meter9,meter10, meter11, meter12,date) "\
  "values (%s,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,NOW());","1000",dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy);
  dummy++;
}
void select_periodic_handler(uint32_t time)
{
  u16_t ret = 0 ;
  char connected = 0 ;
  switch(cs){
    case INIT:
      ret = mysqlc_create(&sd);
      if(!ret){
        cs = CONNECT;
      }
      break;
    case CONNECT:
      ret = mysqlc_connect(&sd,hostname,3306,username,password);
      if(!ret)
        cs = CONNECTING;
      else{
        mysqlc_delete(&sd);
        cs = INIT;
      }
      break;
    case CONNECTING:
      ret = mysqlc_is_connected(&sd,&connected);
      if(ret)
        cs = INIT;/* No connector then recreate it*/
      else if(!connected){
        enum state state;
        ret = mysqlc_get_state(&sd,&state);
        if(ret)
          cs = INIT;/* No connector then recreate it*/
        else if(state != CONNECTOR_STATE_CONNECTING){
          LWIP_DEBUGF(LWIP_DBG_ON, ("select_periodic_handler():Not Connected\n"));
          cs = CONNECT;
        }
      }else{
        cs = CONNECTED;
      }
      break;
    case CONNECTED:
      ret = mysqlc_is_connected(&sd,&connected);
      if(ret)
        cs = INIT;
      else if(!connected){
        LWIP_DEBUGF(LWIP_DBG_ON, ("select_periodic_handler():Not Connected\n"));
        cs =  CONNECT;
        ss = EXECUTE;
      }else{
        switch(ss){
          case EXECUTE:
            {
              enum state state;
              if(time - select_time >  SELECT_PERIOD){
                ret = mysqlc_get_state(&sd,&state);
                if(!ret){
                  if(state == CONNECTOR_STATE_IDLE || state == CONNECTOR_STATE_CONNECTOR_ERROR)
                  {
                    ret = mysqlc_execute(&sd,read_query);
                    if(!ret){
                      ss = READ;
                      LWIP_DEBUGF(LWIP_DBG_ON, ("select_periodic_handler():Reading...\n"));
                    }
                  }
                }else{
                  cs = INIT;
                  ss= EXECUTE;
                }
              }
            }
            break;
          case READ:
            {
              enum state state;
              ret = mysqlc_get_state(&sd,&state);
              if(state == CONNECTOR_STATE_IDLE ){
                column_names* columns = NULL;
                columns = mysqlc_get_columns(&sd);
                if(columns){
                  row_values* row = mysqlc_get_next_row(&sd);
                  if (row != NULL) {
                    long value;
                    LWIP_DEBUGF(LWIP_DBG_ON, ("number of fields is  %d\n",columns->num_fields));
                    for ( int i = 0 ; i < columns->num_fields ; i++){
                      LWIP_DEBUGF(LWIP_DBG_ON, ("%s, ",row->values[i]));
                      //d[i-1] = atol(row->values[i]);
                    }
                  }
                  ss = EXECUTE;
                }
                //ss = EXECUTE;
              }else if(state == CONNECTOR_STATE_CONNECTOR_ERROR ){
                ss = EXECUTE;
              }
            }
            break;
        }
      }
      break;
    default:
      break;
  }
}
