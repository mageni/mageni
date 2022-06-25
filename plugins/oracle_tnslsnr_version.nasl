###############################################################################
# OpenVAS Vulnerability Test
# $Id: oracle_tnslsnr_version.nasl 10929 2018-08-11 11:39:44Z cfischer $
#
# Oracle Version Detection
#
# Authors:
# James W. Abendschan <jwa@jammed.com>
#
# Copyright:
# Copyright (C) 2001 James W. Abendschan <jwa@jammed.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10658");
  script_version("$Revision: 10929 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-11 13:39:44 +0200 (Sat, 11 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Oracle Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Oracle.

  This script sends  'CONNECT_DATA=(COMMAND=VERSION)' command via Oracle
  tnslsnr, a network interface to the remote Oracle database and try to get
  the version from the response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 James W. Abendschan <jwa@jammed.com>");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1521);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");


function tnscmd(sock, command)
{

    command_length = strlen(command);
    packet_length = command_length + 58;

    # packet length - bytes 1 and 2

    plen_h = packet_length / 256;
    plen_l = 256 * plen_h;            # bah, no ( ) ?
    plen_l = packet_length - plen_h;

    clen_h = command_length / 256;
    clen_l = 256 * clen_h;
    clen_l = command_length - clen_l;


    packet = raw_string(
        plen_h, plen_l, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
        0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01,
        clen_h, clen_l, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, command
        );


    send (socket:sock, data:packet);
}

# Reply comes in 2 packets.  The first is the reply to the connection
# request, and if that is successful, the second contains the reply to
# the version request.
#
# The TNS packets come with a 8 byte header and the header contains
# the packet length.  The first 2 bytes of the header are the total
# length of the packet in network byte order.
#
# Steven Procter, Nov 11 2002

function unpack_short(buf, offset)
{
  if( ! buf || ! offset ) return;
  if( ( offset + 1 ) > strlen( buf ) ) return;

  result = ord(buf[offset]) * 256 + ord(buf[offset + 1]);
  return result;
}

function extract_version(socket)
{
  header = recv(socket:socket, length:8, timeout:5);

  if ( strlen(header) < 5 )
     return 0;

  if (ord(header[4]) == 4)
  {
    report = string("A TNS service is running on this port but it\n",
                    "refused to honor an attempt to connect to it.\n",
                    "(The TNS reply code was ", ord(header[4]), ")");
    security_message(port:port, data:report);
    return 0;
  }

  if (ord(header[4]) != 2)
  {
    return 0;
  }

  # read the rest of the accept packet
  tot_len = unpack_short(buf:header, offset:0);
  remaining = tot_len - 8;
  if( remaining < 0 ) return 0;
  rest = recv(socket:socket, length:remaining, timeout:5);

  # next packet should be of type data and the data contains the version string
  header = recv(socket:socket, length:8, timeout:5);
  tot_len = unpack_short(buf:header, offset:0);

  if ( strlen(header) < 5 )
    return 0;

  if (ord(header[4]) != 6)
  {
      return 0;
  }

  # first 2 bytes of the data are flags, the rest is the version string.
  remaining = tot_len - 8;
  if( remaining < 0 ) return 0;
  flags = recv(socket:socket, length:2, timeout:5);
  version = recv(socket:socket, length:remaining - 2, timeout:5);
  return version;
}

function oracle_version(port)
{
  sock = open_sock_tcp(port);
  if (sock)
  {
    cmd = "(CONNECT_DATA=(COMMAND=VERSION))";
    tnscmd(sock:sock, command:cmd);
    version = extract_version(socket:sock);

    if (version == 0)
    {
      return 0;
    }

    ver = eregmatch(pattern:"Version ([0-9.]+)", string:version);

    if(ver[1] == NULL){
      exit(0);
    }

    register_service(port:port, proto:"oracle_tnslsnr");
    set_kb_item(name:"OracleDatabaseServer/installed", value:TRUE);
    set_kb_item(name:"oracle_tnslsnr/" + port + "/version", value:version);
    set_kb_item(name:"OpenDatabase/found", value:TRUE);

    cpe = build_cpe(value: ver[1], exp:"^([0-9.]+)",base:"cpe:/a:oracle:database_server:");
    if(isnull(cpe))
      cpe = 'cpe:/a:oracle:database_server';

    register_product(cpe:cpe, location:port + "/tcp", port:port);

    log_message(data: build_detection_report(app:"Oracle Database Server", version:ver[1],
                                             install:port + "/tcp", cpe:cpe, concluded: ver[1],
                                             port:port));
    close(sock);
  }
}

# retrieve and test unknown services

port = get_unknown_port( default:1521 );

oracle_version(port:port);
