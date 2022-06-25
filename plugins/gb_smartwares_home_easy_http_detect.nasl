# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143110");
  script_version("2019-11-12T03:12:45+0000");
  script_tag(name:"last_modification", value:"2019-11-12 03:12:45 +0000 (Tue, 12 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-12 02:16:34 +0000 (Tue, 12 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Smartwares HOME easy Detection");

  script_tag(name:"summary", value:"Detection of Smartwares HOME easy

  The script sends a connection request to the server and attempts to detect Smartwares HOME easy.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.smartwares.eu/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ('content="HOME easy"' >< res && 'textArray[1]="Password:"' >< res) {
  version = "unknown";

  set_kb_item(name: "smartweares/home_easy/detected", value: TRUE);

  cpe = "cpe:/a:smartweares:home_easy";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Smartwares HOME easy", version: version, install: "/", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
