# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105261");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"creation_date", value:"2015-04-22 13:08:50 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Palo Alto Device Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Palo Alto devices.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

banner = http_get_remote_headers( port:port );

url = "/php/login.php";
res = http_get_cache( port:port, item:url );

# Newer Devices / Firmware (e.g. PA-220) don't have a server banner at all
if( "Server: PanWeb Server/" >< banner ||
    ( "Pan.base.cookie.set" >< res && "BEGIN PAN_FORM_CONTENT" >< res ) ||
    ( "'js/Pan.js'></script>" >< res && ( "/login/images/logo-pan-" >< res || "/images/login-page.gif" >< res ) ) ) {

  # Currently no FW Version / Product name exposed unauthenticated
  model = "unknown";
  version = "unknown";

  set_kb_item( name:"palo_alto/detected", value:TRUE );
  set_kb_item( name:"palo_alto/http/detected", value:TRUE );
  set_kb_item( name:"palo_alto/http/port", value:port );
  set_kb_item( name:"palo_alto/http/" + port + "/version", value:version );
  set_kb_item( name:"palo_alto/http/" + port + "/model", value:model );
  set_kb_item( name:"palo_alto/http/" + port + "/concluded", value:"HTTP(s) Login Page" );
  set_kb_item( name:"palo_alto/http/" + port + "/concludedUrl",
               value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
}

exit( 0 );
