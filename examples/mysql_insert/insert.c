/*
 insert.c
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
  Created on: Aug 25, 2017
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
     insert_periodic_handler(hal_time);


    }


  }

 */

#include "mysql_connector.h"
#include "./insert.h"
#include "lwip/debug.h"


mysqlc_descriptor sd;

// two states (init , loop)
enum connect_states{
  INIT,
  CONNECT,
  CONNECTING,
  CONNECTED
};

const char hostname[] = "192.168.1.69";
const char username[] = "arduino";
const char password[] = "password";

enum connect_states cs = INIT;

#define INSERT_PERIOD  10000

u32_t insert_time = 0 ;

u16_t dummy = 0;
char query[1024];
void construct_query(char query[]){
  sprintf(query,"use powermeter;"\
  "insert into pm_income "\
  "(controller,meter1, meter2, meter3,meter4, meter5, meter6,meter7, meter8, meter9,meter10, meter11, meter12,date) "\
  "values (%s,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,NOW());","1000",dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy,dummy);
  dummy++;
}
void insert_periodic_handler(u32_t time)
{
  int ret = 0 ;
  char connected = 0 ;
  switch (cs) {
    case INIT:
      ret = mysqlc_create(&sd);
      if (!ret) {
        cs = CONNECT;
      }
      break;
    case CONNECT:
      ret = mysqlc_connect(&sd,hostname,3306,username,password);
      if (!ret)
        cs = CONNECTING;
      else{
        mysqlc_delete(&sd);
        cs = INIT;
      }
      break;
     case CONNECTING:
      ret = mysqlc_is_connected(&sd,&connected);
      if (ret)
        cs = INIT;/* No connector then recreate it*/
      else if (!connected){
        enum state state;
        ret = mysqlc_get_state(&sd,&state);
        if(ret)
          cs = INIT;/* No connector then recreate it*/
        else if(state != CONNECTOR_STATE_CONNECTING){
          LWIP_DEBUGF(LWIP_DBG_ON, ("insert_periodic_handler():Not Connected\n"));
          cs = CONNECT;
        }
      }else{
        cs = CONNECTED;
      }
      break;
    case CONNECTED:
      ret = mysqlc_is_connected(&sd,&connected);
      if (ret)
        cs = INIT;
      else if (!connected){
        LWIP_DEBUGF(LWIP_DBG_ON, ("insert_periodic_handler():Not Connected\n"));
        cs =  CONNECT;
      }else{
        enum state state;
        if (time - insert_time >  INSERT_PERIOD) {
          ret = mysqlc_get_state(&sd,&state);
          if (!ret) {
            if (state == CONNECTOR_STATE_IDLE || state == CONNECTOR_STATE_CONNECTOR_ERROR)
            {
              construct_query(query);
              ret = mysqlc_execute(&sd,query);
              if (!ret) {
                insert_time = time;
                LWIP_DEBUGF(LWIP_DBG_ON, ("insert_periodic_handler():Inserting...\n"));
              }
            }
          }else{
            cs = INIT;
          }
        }
      }
      break;
    default:
      break;
  }
}
