##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teltonika_router_http_detect.nasl 12221 2018-11-06 06:30:04Z ckuersteiner $
#
# Teltonika Router Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.141648");
  script_version("$Revision: 12221 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-06 07:30:04 +0100 (Tue, 06 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-06 11:36:23 +0700 (Tue, 06 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Teltonika Router Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Teltonika Router devices.

The script sends a connection request to the server and attempts to detect Teltonika Router devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://teltonika.lt/products/networking/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/cgi-bin/luci");

if ("luci-static/teltonikaExp/hints.js" >< res && "Teltonika solutions" >< res) {
  version = "unknown";

  mod = eregmatch(pattern: "Teltonika-(RUT9[0-9]{2})", string: res);
  if (!isnull(mod[1]))
    model = mod[1];

  set_kb_item(name: "teltonika_router/detected", value: TRUE);

  if (model)
    cpe = 'cpe:/o:teltonika:' + tolower(model) + '_firmware';
  else
    cpe = 'cpe:/o:teltonika:firmware';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Teltonika " + model + " Router", version: version, install: "/",
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
