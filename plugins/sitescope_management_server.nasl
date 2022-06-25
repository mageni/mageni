###############################################################################
# OpenVAS Vulnerability Test
#
# SiteScope Web Managegment Server Detect
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10740");
  script_version("2020-05-04T10:15:51+0000");
  script_tag(name:"last_modification", value:"2020-05-04 10:15:51 +0000 (Mon, 04 May 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SiteScope Web Managegment Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Web application abuses");
  # nb: Don't add a dependency to embedded_web_server_detect.nasl which has a dependency to this VT.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8888);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable the SiteScope Management web server if it is unnecessary,
  or block incoming traffic to this port.");

  script_tag(name:"summary", value:"The remote web server is running the SiteScope Management
  web server.");

  script_tag(name:"impact", value:"This service allows attackers to gain sensitive information on
  the SiteScope-monitored server.

  Sensitive information includes (but is not limited to): license number,
  current users, administrative email addresses, database username and
  password, SNMP community names, UNIX usernames and passwords,
  LDAP configuration, access to internal servers (via Diagnostic tools), etc.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port( default:80 );

foreach url( make_list( "/SiteScope/htdocs/SiteScope.html", "/" ) ) {

  res = http_get_cache( item:url, port:port );

  if( "Freshwater Software" >< res && "URL=SiteScope.html" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  } else if ( "URL=/SiteScope/htdocs/SiteScope.html" >< res && "A HREF=/SiteScope/htdocs/SiteScope.html" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    http_set_is_marked_embedded( port:port );
    exit( 0 );
  }
}

exit( 99 );
