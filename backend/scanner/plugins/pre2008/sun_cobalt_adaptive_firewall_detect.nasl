###############################################################################
# OpenVAS Vulnerability Test
# $Id: sun_cobalt_adaptive_firewall_detect.nasl 13685 2019-02-15 10:06:52Z cfischer $
#
# Sun Cobalt Adaptive Firewall Detection
#
# Authors:
# SecurITeam
#
# Copyright:
# Copyright (C) 2002 SecurITeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10878");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Sun Cobalt Adaptive Firewall Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 SecurITeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8181);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Access to this port (by default set to port 8181) should not be permitted from
  the outside. Further access to the firewall interface itself should not be allowed (by default set to port 2005).");

  script_tag(name:"summary", value:"Sun Cobalt machines contain a firewall mechanism, this mechanism can be
  configured remotely by accessing Cobalt's built-in HTTP server. Upon access to the HTTP server, a java
  based administration program would start, where a user is required to enter a pass phrase in order to
  authenticate himself. Since no username is required, just a passphrase bruteforcing of this interface is
  easier.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8181 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/";
  buf = http_get_cache( item:url, port:port );

  if( "Sun Cobalt Adaptive Firewall" >< buf && "One moment please" >< buf ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    http_set_is_marked_embedded( port:port );
    exit( 0 );
  }
}

exit( 99 );