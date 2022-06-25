###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_omnm_detect.nasl 12249 2018-11-08 02:37:06Z ckuersteiner $
#
# Dell OpenManage Network Manager (OMNM) Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141657");
  script_version("$Revision: 12249 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 03:37:06 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-08 09:03:04 +0700 (Thu, 08 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell OpenManage Network Manager (OMNM) Detection");

  script_tag(name:"summary", value:"Detection of Dell OpenManage Network Manager (OMNM).

The script sends a connection request to the server and attempts to detect Dell OpenManage Network Manager.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.dell.com/en-us/work/shop/povw/dell-openmanage-network-manager");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

res = http_get_cache(port: port, item: "/login");

if ("<title>Login - OMNM</title>" >< res && "/html/js/barebone.jsp" >< res) {
  version = "unknown";

  set_kb_item(name: "dell_omnm/detected", value: TRUE);

  cpe = 'cpe:/a:dell:openmanage_network_manager';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Dell OpenManage Network Manager", version: version, install: "/",
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
