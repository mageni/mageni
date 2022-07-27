###################################################################
# OpenVAS Vulnerability Test
# $Id: yahoo_msg_running.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Yahoo Messenger Detection
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102001");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:34:11 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Yahoo Messenger Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 LSS");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 5101);

  script_xref(name:"URL", value:"http://libyahoo2.sourceforge.net/ymsg-9.txt");
  script_xref(name:"URL", value:"http://www.astahost.com/info.php/yahoo-protocol-part-10-peer-peer-transfers_t11490.html");
  script_xref(name:"URL", value:"http://libyahoo2.sourceforge.net/README");
  script_xref(name:"URL", value:"http://www.ycoderscookbook.com/");
  script_xref(name:"URL", value:"http://www.venkydude.com/articles/yahoo.htm");

  script_tag(name:"summary", value:"Yahoo Messenger is running on this machine and this port. It can
  be used to share files and chat with other users.

  Tested with Yahoo Messenger versions 7 and 8.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

#YMSG    - The first four bytes of all packets are always YMSG - the
#          protocol name.

ymsg = string("YMSG");

#version - The next four bytes are for the protocol version number.
#          For version 9, these are 0x09 0x00 0x00 0x00
#          NOTE: The last three bytes of this may just be padding bytes.
#          NOTE: In the network byte order version field looks
#          like 0x00 0x09 0x00 0x00, last 2 bytes represent zero padding.
#nb: using Yahoo Messenger 7! Wireshark shows YMSG version 13 (hex 0x0d).
#The latest version of YahooMsg 9 uses YMSG 16 (hex 0x10)
version = raw_string(0x00 ,0x10 ,0x00 ,0x00);


#pkt_len - A two byte value, in network byte order, stating how many bytes
#          are in the _data_ section of the packet.  In practice, this
#          value does not exceed about 1000.

pkt_len = raw_string( 0x00, 0x00);

#later on when we craft the data section of the packet we will
#update pkt_len field

#service - This is an opcode that tells the client/server what kind of
#          service is requested/being responded to.  There are 45 known
#          services.
#         We will try to use:
#         1) P2PFILEXFER = 0x4d  - transfer a file between two peers,
#          yahoo server not used!!!
#         - 2 bytes

service = raw_string( 0x00, 0x4d);


#status  - In case of a response from the server, indicates the status
#          of the request (success/failure/etc.).  For a request, it is 0
#          in most cases, except for packets that set the user's status
#          (set status, typing notify, etc.)
#       - 4 bytes

#status states that we are available

status = raw_string(0x00, 0x00, 0x00, 0x00);


#session - The session id is used primarily when connecting through a HTTP
#id        proxy.  It is set in all cases, but has no effect in a direct
#          connection.  When the client sends the first packet, it is 0,
#          the server responds with a session id that is used by the client
#          and the server in all further packets.  The server may change
#          the session id, in which case the client must use the new
#          session id henceforth.

#we put some junk inside sesion_id

session_id = raw_string(0x00,0x00,0x00,0x00);


#DATA    - The data section is pkt_len bytes long and consists of a series
#          of key/value pairs.  All keys are numeric strings.  The packet
#          contains their numeric values in the ASCII character set. e.g.
#          1 == 0x31, 21 == 0x32 0x31
#          Every key and value is terminated by a two byte sequence of
#          0xc0 0x80.  Some keys may have empty values.
#          The actual keys sent, and their meanings depend on the service
#          in use.

separator = raw_string(0xc0, 0x80);
crap_len = 512;

#NOTE: YMSG 7 gives a response for a request with any value for key 5,
#while YMSG 9 seems to respond only to CORRECT 5 key value (correct user_id)

first_key_value_pair = string( "4" + separator + "bladyjoker" + separator);
second_key_value_pair = string( "241" + separator + "0" + separator);
third_key_value_pair = string( "5" + separator + "bladyjoker" + separator);
fourth_key_value_pair = string( "13" + separator + "5" + separator);
fifth_key_value_pair = string( "49" + separator + "PEERTOPEER" + separator);


data =   first_key_value_pair
        + second_key_value_pair
        + third_key_value_pair
        + fourth_key_value_pair
        + fifth_key_value_pair;


pkt_len = raw_string(0x00, 0x3D); #data section length in bytes

yahoo_pkt = ymsg + version + pkt_len + service + status + session_id + data;
yahoo_pkt_len = strlen(yahoo_pkt);

port = get_unknown_port( default:5101 ); #Yahoo Messeger client listening port!!! FILE SHARING

sock = open_sock_tcp( port );

if( sock ) {

  send( socket:sock, data:yahoo_pkt, length:yahoo_pkt_len );
  recv_buffer = recv( socket:sock, length:256 );
  close( sock );

  if( "YMSG" >< recv_buffer ) {
    set_kb_item( name:"yahoo_messenger/installed", value:TRUE );
    register_service( port:port, proto:"yahoo_messenger" );
    log_message( port:port );
  }
}

exit( 0 );