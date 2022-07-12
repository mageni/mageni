###############################################################################
# OpenVAS Vulnerability Test
# $Id: www_multiple_get.nasl 13685 2019-02-15 10:06:52Z cfischer $
#
# Several GET locks web server
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.18366");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Several GET locks web server");
  # It is not really destructive, but it is useless in safe_checks mode
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote web server shuts down temporarily or blacklists
  us when it receives several GET HTTP/1.0 requests in a row.

  This might trigger false positive in generic destructive or DoS plugins.

  The scanner enabled some countermeasures, however they might be
  insufficient.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );
if( http_get_is_marked_embedded( port:port ) )
  exit( 0 );

# CISCO IP Phone 7940 behaves correctly on a HTTP/1.1 request,
# so we forge a crude HTTP/1.0 request.

if( http_is_dead( port:port, retry:4 ) ) exit( 0 );

host = http_host_name( port:port );

req = string( "GET / HTTP/1.0\r\n",
              "Host: ", host, "\r\n" );
max = 12;

for( i = 0; i < max; i++ ) {
  recv = http_send_recv( port:port, data:req );
  if( ! recv )
    break;
}

if( i == 0 ) {
  # nb: Server is dead?
} else if( i < max ) {
  set_kb_item( name:'www/multiple_get/' + port, value:i );
  log_message( port:port );
  exit( 0 );
}

exit( 99 );