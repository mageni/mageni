# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143323");
  script_version("2020-01-15T08:02:23+0000");
  script_tag(name:"last_modification", value:"2020-01-15 08:02:23 +0000 (Wed, 15 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-08 07:50:11 +0000 (Wed, 08 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ruckus Unleashed Detection");

  script_tag(name:"summary", value:"Detection of Ruckus Unleashed.

  The script sends a connection request to the server and attempts to detect Ruckus Unleashed devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.ruckuswireless.com/products/system-management-control/unleashed");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/admin/login.jsp");

if ("<title>Unleashed Login</title>" >< res && "ruckus_logo" >< res) {
  version = "unknown";

  set_kb_item(name: "ruckus/unleashed/detected", value: TRUE);

  app_cpe = "cpe:/a:ruckuswireless:unleashed_firmware";
  os_cpe = "cpe:/o:ruckuswireless:unleashed_firmware";
  hw_cpe = "cpe:/h:ruckuswireless:unleashed";

  register_and_report_os(os: "Ruckus Unleashed Firmware", cpe: os_cpe, desc: "Ruckus Unleashed Detection",
                         runs_key: "unixoide");

  register_product(cpe: app_cpe, location: "/", port: port, service: "www");
  register_product(cpe: os_cpe, location: "/", port: port, service: "www");
  register_product(cpe: hw_cpe, location: "/", port: port, service: "www");

  report = log_message(data: build_detection_report(app: "Ruckus Unleashed", version: version, install: "/",
                                                    cpe: app_cpe),
                       port: port);
  exit(0);
}

exit(0);
