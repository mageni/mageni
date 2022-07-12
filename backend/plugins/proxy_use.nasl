###############################################################################
# OpenVAS Vulnerability Test
# $Id: proxy_use.nasl 8142 2017-12-15 13:00:23Z cfischer $
#
# HTTP Proxy Server Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100083");
  script_version("$Revision: 8142 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:00:23 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-28 19:13:00 +0100 (Sat, 28 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HTTP Proxy Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Firewalls");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/http_proxy", 3128, 8080, 6588, 8000, 8888, "Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Limit access to the proxy to valid users and/or valid hosts.");

  script_tag(name:"summary", value:"A HTTP proxy server is running at this Host and accepts
  unauthenticated requests from the Scanner.");

  script_tag(name:"insight", value:"An open proxy is a proxy server that is accessible by any
  Internet user. Generally, a proxy server allows users within a network group to store and
  forward Internet services such as DNS or web pages to reduce and control the bandwidth used
  by the group. With an open proxy, however, any user on the Internet is able to use this
  forwarding service.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = get_kb_list( "Services/http_proxy" );
if( ! ports ) ports = make_list( "3128", "8080", "6588", "8000", "80", "8888" );

url = 'http://www.openvas.org/openvas-proxy-test';

foreach port( ports ) {

  if( ! get_port_state( port ) ) continue;

  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf == NULL ) continue;

  if ( "%%openvas-proxy-test%%" >< buf ) {

    set_kb_item( name:"Proxy/usage", value:TRUE );
    set_kb_item( name:"Services/http_proxy", value:port );

    if( egrep( pattern: "squid", string: buf, icase:TRUE ) ) {
      set_kb_item( name:"www/squid", value:TRUE );
    }

    if( VIA = egrep( pattern: "^Via:.*$", string: buf ) ) {
      if( VIA = eregmatch( pattern: "^Via: (.*)$", string: VIA ) ) {
        set_kb_item( name:"Proxy/" + port  + "/via", value: chomp( VIA[1] ) );
      }
    }
    log_message( port:port );
  }
}

exit( 0 );
