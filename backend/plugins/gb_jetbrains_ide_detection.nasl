###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetbrains_ide_detection.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# JetBrains IDE Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107232");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-25 11:19:19 +0700 (Fri, 25 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("JetBrains IDE Detection");

  script_tag(name:"summary", value:"Detection of JetBrains IDE products.

This script tries to detect various JetBrains IDE products via HTTP GET request.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080, 8090, 63342);
  script_mandatory_keys("JetBrainsIDEs/banner");

  script_xref(name:"URL", value:"https://www.jetbrains.com/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("misc_func.inc" );
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default: 8090 );

banner = get_http_banner( port: port );

if ( !banner && ( "server: PyCharm" >!< banner || "server: WebStorm" >!< banner || "server: CLion" >!< banner ||
     "server: DataGrip" >!< banner || "server: IntelliJ IDEA" >!< banner || "server: JetBrains MPS" >!< banner ||
     "server: PyCharm Edu" >!< banner || "server: jetBrains Rider" >!< banner || "server: RubyMine" >!< banner ) )
  exit(0);

set_kb_item( name: "jetBrains/installed", value: TRUE);


random = rand_str( length: 13, charset: "0123456789" );
url = "/api/about?more-true?a=" + random;

req = http_get_req( port: port, url: url, add_headers: make_array( 'Content-Type', 'application/xml', 'Connection', 'close' ) );
res = http_keepalive_send_recv( port: port, data: req );

IDE_version = "unknown";

name = eregmatch( pattern: 'name": "(PyCharm|WebStorm|CLion|DataGrip|IntelliJ|JetBrains|JetBrains|jetBrains|RubyMine).*([0-9.]+)",', string: res );

if (!isnull(name)) {
  IDE_name = name [1];
  IDE_version = name [2];
  set_kb_item( name: "jetBrains/ide", value: IDE_name );
}

configPath = eregmatch( pattern: 'configPath": "(.*)config",', string: res);

if (!isnull(configPath[1])) {
  configPath = configPath[1] + "config";
  set_kb_item( name: "jetBrains/configpath", value: configPath );
}

homePath = eregmatch( pattern: 'homePath": "(.*)"', string: res);

if (!isnull(homePath[1])) {
  homePath = homePath[1];
  set_kb_item( name: "jetBrains/homepath", value: homePath);
}

cpe = build_cpe( value: IDE_version, exp: "^([0-9.]+)", base: "cpe:/a:jetbrains:jetbrains:" );
if (!cpe)
  cpe = "cpe:/a:jetbrains:jetbrains";

register_product( cpe: cpe, port: port, location: "/" );

log_message(data: build_detection_report( app: "jetBrains " + IDE_name , version: IDE_version, install: "/",
                                          cpe: cpe, concluded: name, concludedUrl: url),
            port: port );

exit( 0 );
