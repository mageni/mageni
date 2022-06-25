###############################################################################
# OpenVAS Vulnerability Test
# $Id: cvsweb_version.nasl 6053 2017-05-01 09:02:51Z teissa $
#
# CVSWeb detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
# - script id
# - more verbose report
# - hole -> warning
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10402");
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CVSWeb detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Restrict the access to this CGI using password protection
  or disable it if you do not use it.");
  script_tag(name:"summary", value:"CVSWeb is used by hosts to share programming source
  code. Some web sites are misconfigured and allow access to their sensitive source code without
  any password protection.

  This plugin tries to detect the presence of a CVSWeb CGI and when it finds it, it tries to obtain its version.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/cvsweb.cgi/";
  req = http_get( item:url, port:port);
  res = http_keepalive_send_recv( port:port, data:req );

  if( "CVSweb $Revision:" >< res ) {

    result = strstr( res, string( "CVSweb $Revision: " ) );
    result = result - strstr( result, string( " $ -->\n" ) );
    result = result - "CVSweb $Revision: ";
    set_kb_item( name:"www/" + port + "/cvsweb/version", value:result );
    result = string( "The installed version of this CGI is : ", result );

    security_message( port:port, data:result );
    exit( 0 );
  }
}

exit( 99 );
