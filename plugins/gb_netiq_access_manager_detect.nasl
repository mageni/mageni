###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netiq_access_manager_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# NetIQ Access Manager Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105148");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-19 14:59:27 +0100 (Fri, 19 Dec 2014)");
  script_name("NetIQ Access Manager Detection");

  script_tag(name:"summary", value:"The script sends a connection
request to the server and attempts to determine if the remote host runs
NetIQ Access Manager from the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.netiq.com/products/access-manager/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:443 );

url = '/nidp/app';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>NetIQ Access Manager" >!< buf || "" >!< buf ) exit( 0 );

set_kb_item(name:"netiq_access_manager/installed", value:TRUE);
version = "unknown";
version_url = "/nidp/html/help/en/bookinfo.html";

version_resp = http_get_cache( item:version_url, port:port );
version_match = eregmatch ( pattern:"NetIQ Access Manager ([0-9.]+) User Portal Help", string:version_resp );

if ( version_match[1] ) {
  version = version_match[1];
  concluded_url = report_vuln_url( port:port, url:version_url, url_only:TRUE);
}

register_and_report_cpe( app: "NetIQ Access Manager", ver: version, concluded: version_match[0], base: "cpe:/a:netiq:access_manager:" , expr: '([0-9.]+)', insloc: url, regPort: port, conclUrl: concluded_url );

exit( 0 );
