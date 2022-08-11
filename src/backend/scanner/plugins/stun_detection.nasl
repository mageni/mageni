###############################################################################
# OpenVAS Vulnerability Test
# $Id: stun_detection.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Detect STUN Server
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11986");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detect STUN Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Service detection");
  script_require_udp_ports("Services/udp/stun", 3478);

  script_tag(name:"solution", value:"If this service is not needed, disable it or filter incoming traffic
  to this port.");

  script_tag(name:"summary", value:"A VPN server is listening on the remote port.

  Description :

  The remote host is running a STUN (Simple Traversal of User Datagram
  Protocol - RFC 3489) server.

  Simple Traversal of User Datagram Protocol (UDP) Through Network
  Address Translators (NATs) (STUN) is a lightweight protocol that
  allows applications to discover the presence and types of NATs and
  firewalls between them and the public Internet.  It also provides the
  ability for applications to determine the public Internet Protocol
  (IP) addresses allocated to them by the NAT.  STUN works with many
  existing NATs, and does not require any special behavior from them.
  As a result, it allows a wide variety of applications to work through
  existing NAT infrastructure.

  Make sure the use of this software is done in accordance with your corporate
  security policy.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("global_settings.inc");
include("misc_func.inc");
include("dump.inc");

debug = debug_level;

port = get_kb_item( "Services/udp/stun" );
if( ! port ) port = 3478;

if( ! get_udp_port_state( port ) ) exit( 0 );

udpsock = open_sock_udp(port);
data = raw_string(0x00, 0x01, # Binding request
                  0x00, 0x08, # Message length
                  0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, # Message ID
                  0x00, 0x03, # Change-Request
                  0x00, 0x04, # Attribute length
                  0x00, 0x00, 0x00, 0x00 # Not Set, Not Set
                 );

send(socket:udpsock, data:data);

response = "";

z = recv(socket:udpsock, length:1024, min:1);
if(z)
{
 if (debug)
 {
  dump(dtitle:"STUN", ddata:z);
 }

 if (z[0] == raw_string(0x01) && z[1] == raw_string(0x01)) # Binding Response
 {
  length = ord(z[2])*256 + ord(z[3]);

  if (debug)
  {
   display("length: ", length, "\n");
  }

  offset = 2+2+16;
  for (i = 0; i < length;)
  {
   count = 0;
   if (z[i+offset] == raw_string(0x00) && z[i+1+offset] == raw_string(0x01)) # Mapped address
   {
    count += 2;
    if (z[i+count+offset] == raw_string(0x00) && z[i+count+1+offset] == raw_string(0x08)) # Attribute length should be 8
    {
     count += 2;
     if (z[i+count+1+offset] == raw_string(0x01)) # IPv4
     {
      count += 2;
      port = ord(z[i+count+offset])*256+ord(z[i+count+1+offset]);
      ip = string(ord(z[i+count+2+offset]), ".", ord(z[i+count+3+offset]), ".", ord(z[i+count+4+offset]), ".", ord(z[i+count+5+offset]));
      count += 6;

      response = string(response, "Mapped Address: ", ip, ":", port, "\n");
#      display("Mapped address\n");
#      display("port: ", port, "\n");
#      display("ip: ", ip, "\n");
     }
    }
   }

   if (z[i+offset] == raw_string(0x00) && z[i+1+offset] == raw_string(0x04)) # Source Address
   {
    count += 2;
    if (z[i+count+offset] == raw_string(0x00) && z[i+count+1+offset] == raw_string(0x08)) # Attribute length should be 8
    {
     count += 2;
     if (z[i+count+1+offset] == raw_string(0x01)) # IPv4
     {
      count += 2;
      port = ord(z[i+count+offset])*256+ord(z[i+count+1+offset]);
      ip = string(ord(z[i+count+2+offset]), ".", ord(z[i+count+3+offset]), ".", ord(z[i+count+4+offset]), ".", ord(z[i+count+5+offset]));
      count += 6;

      response = string(response, "Source Address: ", ip, ":", port, "\n");
#      display("Source Address\n");
#      display("port: ", port, "\n");
#      display("ip: ", ip, "\n");
     }
    }
   }

   if (z[i+offset] == raw_string(0x00) && z[i+1+offset] == raw_string(0x05)) # Changed Address
   {
    count += 2;
    if (z[i+count+offset] == raw_string(0x00) && z[i+count+1+offset] == raw_string(0x08)) # Attribute length should be 8
    {
     count += 2;
     if (z[i+count+1+offset] == raw_string(0x01)) # IPv4
     {
      count += 2;
      port = ord(z[i+count+offset])*256+ord(z[i+count+1+offset]);
      ip = string(ord(z[i+count+2+offset]), ".", ord(z[i+count+3+offset]), ".", ord(z[i+count+4+offset]), ".", ord(z[i+count+5+offset]));
      count += 6;

      response = string(response, "Changed Address: ", ip, ":", port, "\n");
#      display("Changed Address\n");
#      display("port: ", port, "\n");
#      display("ip: ", ip, "\n");
     }
    }
   }

   if (count == 0)
   {
    if (debug)
    {
     display("z[i(", i, ")+offset(", offset, ")]: ", ord(z[i+offset]), "\n");
    }
    i++;
   }

   i += count;
  }

  if (response)
  {
   desc += '\n\nPlugin output :\n\n' + response;
   log_message(port:port, proto:"udp", data:desc);
   register_service(port: port, proto: "stun", ipproto: "udp");
   exit(0);
  }
 }
}