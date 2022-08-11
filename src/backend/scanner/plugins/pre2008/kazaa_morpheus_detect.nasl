###############################################################################
# OpenVAS Vulnerability Test
# $Id: kazaa_morpheus_detect.nasl 6695 2017-07-12 11:17:53Z cfischer $
#
# Kazaa / Morpheus Client Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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

# 2002-06-08 Michel Arboi
# The script did not detect the latest versions of the Kazaa software.
# The session is:
# GET / HTTP/1.0
#
# HTTP/1.0 404 Not Found
# X-Kazaa-Username: xxxx
# X-Kazaa-Network: KaZaA
# X-Kazaa-IP: 192.168.192.168:1214
# X-Kazaa-SupernodeIP: 10.10.10.10:1214

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10751");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Kazaa / Morpheus Client Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Peer-To-Peer File Sharing");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 1214);
  script_mandatory_keys("X-Kazaa-Username/banner");

  script_xref(name:"URL", value:"http://www.securiteam.com/securitynews/5UP0L2K55W.html");

  script_tag(name:"solution", value:"Currently there is no way to limit this exposure.
  Filter incoming traffic to this port.");

  script_tag(name:"summary", value:"The Kazaa / Morpheus HTTP Server is running.
  This server is used to provide other clients with a
  connection point. However, it also exposes sensitive system files.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:1214 );
banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );

# if (egrep(pattern:"^Server: KazaaClient", string:resultrecv))
if( "X-Kazaa-Username: " >< banner ) {

  buf = strstr( banner, "X-Kazaa-Username: " );
  buf = buf - "X-Kazaa-Username: ";
  subbuf = strstr( buf, string( "\r\n" ) );
  buf = buf - subbuf;
  username = buf;
  if(!username)
    exit(0);

  buf = "Remote host reported that the username used is: ";
  buf = buf + username;

  set_kb_item( name:"kazaa/username", value:username );
  security_message( data:buf, port:port );
  exit( 0 );
}

exit( 99 );