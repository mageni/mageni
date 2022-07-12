###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hyperip_http_detect.nasl 8951 2018-02-26 11:47:22Z cfischer $
#
# NetEx HyperIP Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108348");
  script_version("$Revision: 8951 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-26 12:47:22 +0100 (Mon, 26 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetEx HyperIP Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the remote host and attempts
  to detect the presence of NetEx HyperIP virtual appliance.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

buf = http_get_cache( item:"/", port:port );

if( "<TITLE>HyperIP Home</TITLE>" >< buf ) {

  version = "unknown";

  url = "/bstatus.php";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  # <span id="hyperipCurVer">6.1.1</span></td>
  vers = eregmatch( pattern:'hyperipCurVer">([0-9.]+)</span>', string:buf );
  if( vers[1] ) {
    version = vers[1];
    set_kb_item( name:"hyperip/http/" + port + "/concluded", value:vers[0] );
    set_kb_item( name:"hyperip/http/" + port + "/concludedUrl", value:report_vuln_url( port:port, url:url, url_only:TRUE ) );
  }

  set_kb_item( name:"hyperip/http/" + port + "/version", value:version );
  set_kb_item( name:"hyperip/detected", value:TRUE );
  set_kb_item( name:"hyperip/http/detected", value:TRUE );
  set_kb_item( name:"hyperip/http/port", value:port );
}


exit( 0 );
