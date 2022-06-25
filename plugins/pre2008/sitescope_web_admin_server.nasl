###############################################################################
# OpenVAS Vulnerability Test
# $Id: sitescope_web_admin_server.nasl 4094 2016-09-16 14:12:07Z mime $
#
# SiteScope Web Administration Server Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10741");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SiteScope Web Administration Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 2525);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable the SiteScope Administration web server if it is unnecessary,
  or block incoming traffic to this port.");

  script_tag(name:"summary", value:"The remote web server is running the SiteScope Administration
  web server. This server enables attackers to configure your SiteScope product
  (Firewall monitoring program) if they gain access to a valid authentication
  username and password or to gain valid usernames and passwords using a brute force attack.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:2525 );

buf = http_get_cache( item:"/", port:port );

if( "401 Unauthorized" >< buf && "WWW-Authenticate: BASIC realm=" >< buf && "SiteScope Administrator" >< buf ) {
  report = report_vuln_url( port:port, url:"/" );
  log_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );