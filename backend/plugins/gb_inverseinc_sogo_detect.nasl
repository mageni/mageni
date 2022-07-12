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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142120");
  script_version("$Revision: 14092 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 11:10:08 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-11 16:02:17 +0700 (Mon, 11 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SOGo Detection");

  script_tag(name:"summary", value:"Detection of SOGo.

The script sends a connection request to the server and attempts to detect SOGo and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://sogo.nu/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/SOGo/");

if ('content="SOGo Web Interface"' >< res && "SOGo.woa" >< res) {
  version = "unknown";

  # <p>Version 4.0.4 (@shiva2.inverse 201812030202)</p>
  vers = eregmatch(pattern: "<p>Version ([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "inverse/sogo/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:inverse-inc:sogo:");
  if (!cpe)
    cpe = "cpe:/a:inverse-inc:sogo";

  register_product(cpe: cpe, location: "/SOGo", port: port, service: "www");

  log_message(data: build_detection_report(app: "SOGo", version: version, install: "/SOGo", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
