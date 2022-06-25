###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libelium_meshlium_detect.nasl 11251 2018-09-06 03:21:13Z ckuersteiner $
#
# Libelium Meshlium IoT Gateway Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141430");
  script_version("$Revision: 11251 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-06 05:21:13 +0200 (Thu, 06 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-05 16:20:51 +0700 (Wed, 05 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Libelium Meshlium IoT Gateway Detection");

  script_tag(name:"summary", value:"Detection of Libelium Meshlium IoT Gateway.

The script sends a connection request to the server and attempts to detect Libelium Meshlium IoT Gateway and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.libelium.com/products/meshlium/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/ManagerSystem/login.php");

if ("<title>Meshlium Manager System</title>" >< res && "Libelium Comunicaciones" >< res) {
  version = "unknown";

  url = "/MeshliumInfo/";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);
  vers = eregmatch(pattern: "ManagerSystem Version</td>[^>]+>([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  mac = eregmatch(pattern: "MAC</td>[^>]+>([0-9a-f:]{17})", string: res);
  if (!isnull(mac[1])) {
    register_host_detail(name: "MAC", value: mac[1], desc: "gb_libelium_meshlium_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
    extra += '\nMAC Address:   ' + mac[1];
  }

  set_kb_item(name: "libelium_meshlium/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:libelium:meshlium:");
  if (!cpe)
    cpe = 'cpe:/a:libelium:meshlium';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Libelium Meshlium", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
