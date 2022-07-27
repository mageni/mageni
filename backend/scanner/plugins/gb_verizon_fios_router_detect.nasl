# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.142240");
  script_version("2019-04-11T08:25:12+0000");
  script_tag(name:"last_modification", value:"2019-04-11 08:25:12 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-11 06:04:26 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Verizon Fios Router Detection");

  script_tag(name:"summary", value:"Detection of Verizon Fios Routers.

The script sends a connection request to the server and attempts to detect Verizon Fios routers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443, 8080, 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.verizon.com/home/accessories/fios-quantum-gateway/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8443);

res =  http_get_cache(port: port, item: "/");

if ("<title>Verizon Router</title>" >< res && 'ng-app="vzui"' >< res) {
  version = "unknown";

  set_kb_item(name: "verizon/fios_router/detected", value: TRUE);

  cpe = 'cpe:/h:verizon:fios_router';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Verizon Fios Router", version: version, install: "/", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
