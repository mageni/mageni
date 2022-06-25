###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sierrawireless_acemanager_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Sierra Wireless AceManager Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106075");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-17 08:27:15 +0700 (Tue, 17 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_active");

  script_name("Sierra Wireless AceManager Detection");

  script_tag(name:"summary", value:"Detection of Sierra Wireless AceManager

The script sends a connection request to the server and attempts to detect Sierra Wireless AceManager which
is a web based utility to manage and configure AirLink devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.sierrawireless.com/");



  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:9443);

res = http_get_cache(item: "/", port: port);

if ("Server: Sierra Wireless Inc, Embedded Server" >< res && "<title>::: ACEmanager :::</title>" >< res &&
"Sierra Wireless, Inc." >< res) {
  vers = string("unknown");

  set_kb_item(name: string("www/", port, "/acemanager"), value: vers);
  set_kb_item(name: "sierra_wireless_acemanager/installed", value: TRUE);

  cpe = 'cpe:/h:sierra_wireless:acemanager';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Sierra Wireless AceManager", version: vers, install: "/",
                                           cpe: cpe),
              port: port);
}

exit(0);
