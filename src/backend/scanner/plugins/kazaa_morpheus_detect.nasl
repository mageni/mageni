###############################################################################
# OpenVAS Vulnerability Test
#
# Kazaa / Morpheus Client Detection (HTTP)
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2005 SecuriTeam
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
  script_version("2021-03-22T07:55:33+0000");
  script_tag(name:"last_modification", value:"2021-03-22 07:55:33 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Kazaa / Morpheus Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 1214);
  script_mandatory_keys("X-Kazaa-Username/banner");

  script_tag(name:"summary", value:"HTTP based detection of the Kazaa / Morpheus server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:1214 );
banner = http_get_remote_headers( port:port );
if( ! banner )
  exit( 0 );

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
  log_message( data:buf, port:port );
}

exit( 0 );
