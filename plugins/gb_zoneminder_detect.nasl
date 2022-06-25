###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoneminder_detect.nasl 12872 2018-12-21 14:36:20Z asteins $
#
# ZoneMinder Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106520");
  script_version("$Revision: 12872 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 15:36:20 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-01-17 13:28:38 +0700 (Tue, 17 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZoneMinder Detection");

  script_tag(name:"summary", value:"Detection of ZoneMinder

The script sends a HTTP connection request to the server and attempts to detect the presence of ZoneMinder.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir (make_list_unique("/zm", "/zoneminder", cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/") dir = "";

  res = http_get_cache(port: port, item: dir + "/index.php");

  if (("<h1>ZoneMinder Login</h1>" >< res || res =~ "<title>Zone[mM]inder - Console</title>" >< res ) &&
      "var skinPath" >< res) {

    version = "unknown";

    req = http_get(port: port, item: dir + "/index.php?view=version");
    res = http_keepalive_send_recv(port: port, data: req);

    vers = eregmatch(pattern: "ZoneMinder, v([0-9]+\.[0-9]+\.[0-9]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "zoneminder/version", value: version);
    }

    set_kb_item(name: "zoneminder/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:zoneminder:zoneminder:");
    if (!cpe)
      cpe = 'cpe:/a:zoneminder:zoneminder';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "ZoneMinder", version: version, install: install, cpe: cpe,
                                             concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
