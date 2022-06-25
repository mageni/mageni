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
  script_oid("1.3.6.1.4.1.25623.1.0.142516");
  script_version("2019-06-28T06:52:39+0000");
  script_tag(name:"last_modification", value:"2019-06-28 06:52:39 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-28 05:59:08 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetData Detection");

  script_tag(name:"summary", value:"Detection of NetData.

  The script sends a connection request to the server and attempts to detect NetData and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 443, 8000);
  script_mandatory_keys("NetData/banner");

  script_xref(name:"URL", value:"https://my-netdata.io/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

port = get_http_port(default: 8000);

banner = get_http_banner(port: port);
if ("NetData Embedded HTTP Server" >!< banner)
  exit(0);

version = "unknown";

# Server: NetData Embedded HTTP Server v1.15.0-122-g1f28a4d7
vers = eregmatch(pattern: "NetData Embedded HTTP Server v([0-9.]+)", string: banner);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "netdata/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:my-netdata:netdata:");
if (!cpe)
  cpe = "cpe:/a:my-netdata:netdata";

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "NetData", version: version, install: "/", cpe: cpe,
                                         concluded: vers[0]),
            port: port);

exit(0);
