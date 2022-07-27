###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vibnode_http_detect.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# PRUFTECHNIK VIBNODE Detection (HTTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108341");
  script_version("$Revision: 10901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-16 10:43:37 +0100 (Fri, 16 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PRUFTECHNIK VIBNODE Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the remote host and attempts
  to detect the presence of a PRUFTECHNIK VIBNODE device.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");


port = get_http_port( default:80 );
banner = get_http_banner( port:port );

if( banner =~ "^HTTP/1\.[01] 401" && 'WWW-Authenticate: Basic realm="VibNode"' >< banner ) {

  app_version = "unknown";
  os_version  = "unknown";
  set_kb_item( name:"vibnode/detected", value:TRUE );
  set_kb_item( name:"vibnode/http/detected", value:TRUE );
  set_kb_item( name:"vibnode/http/port", value:port );
  set_kb_item( name:"vibnode/http/" + port + "/concluded", value:banner );
  set_kb_item( name:"vibnode/http/" + port + "/app_version", value:app_version );
  set_kb_item( name:"vibnode/http/" + port + "/os_version", value:os_version );
}

exit( 0 );
