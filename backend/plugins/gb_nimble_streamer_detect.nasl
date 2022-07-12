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
  script_oid("1.3.6.1.4.1.25623.1.0.142788");
  script_version("2019-08-26T07:31:18+0000");
  script_tag(name:"last_modification", value:"2019-08-26 07:31:18 +0000 (Mon, 26 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-26 05:51:44 +0000 (Mon, 26 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Nimble Streamer Detection");

  script_tag(name:"summary", value:"Detection of Nimble Streamer

  The script sends a connection request to the server and attempts to detect Nimble Streamer and to extract
  its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 8081);
  script_mandatory_keys("Nimble/banner");

  script_xref(name:"URL", value:"https://wmspanel.com/nimble");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

port = get_http_port(default: 8081);

banner = get_http_banner(port: port);

if (banner =~ "Server: Nimble/") {
  version = "unknown";

  # Server: Nimble/3.6.0-1
  vers = eregmatch(pattern: "Nimble/([0-9.-]+)", string: banner);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "nimble_streamer/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/a:softvelum:nimble_streamer:");
  if (!cpe)
    cpe = "cpe:/a:softvelum:nimble_streamer";

  register_product(cpe: cpe, port: port, location: "/", service: "www");

  log_message(data: build_detection_report(app: "Nimble Streamer", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
