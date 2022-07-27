##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_peplink_balance_webadmin_detect.nasl 10906 2018-08-10 14:50:26Z cfischer $
#
# Peplink Balance Routers Web Admin Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.106847");
  script_version("$Revision: 10906 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-06-06 10:26:12 +0700 (Tue, 06 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Peplink Balance Routers Web Admin Detection");

  script_tag(name:"summary", value:"Detection of Peplink Balance Routers Web Admin.

The script sends a connection request to the server and attempts to detect the Web Admin Interface of Peplink
Balance Routers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.peplink.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8081);

res = http_get_cache(port: port, item: "/cgi-bin/MANGA/index.cgi");

if ("<title>Web Admin" >< res && 'oemid = "PEPLINK"' >< res) {
  version = "unknown";

  set_kb_item(name: "peplink_balance/detected", value: TRUE);

  cpe = "cpe:/a:peplink:balance";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Peplink Balance Router", version: version, install: "/",
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
