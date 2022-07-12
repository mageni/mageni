###############################################################################
# OpenVAS Vulnerability Test
#
# Cobalt Web Administration Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10793");
  script_version("2020-05-04T10:15:51+0000");
  script_tag(name:"last_modification", value:"2020-05-04 10:15:51 +0000 (Mon, 04 May 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cobalt Web Administration Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 81);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable the Cobalt Administration web server if
  you do not use it, or block inbound connections to this port.");

  script_tag(name:"summary", value:"The remote web server is the Cobalt Administration web server.");

  script_tag(name:"impact", value:"This web server enables attackers to configure your Cobalt server
  if they gain access to a valid authentication username and password.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port( default:81 );

url = "/admin";
res = http_get_cache( item:url, port:port );

if( "401 Authorization Required" >< res && ( ( "CobaltServer" >< res ) || ( "CobaltRQ" >< res ) ) && ( "WWW-Authenticate: Basic realm=" >< res ) ) {
  http_set_is_marked_embedded( port:port );
  report = http_report_vuln_url( port:port, url:url );
  log_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );
