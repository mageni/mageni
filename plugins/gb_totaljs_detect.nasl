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
  script_oid("1.3.6.1.4.1.25623.1.0.142118");
  script_version("$Revision: 14084 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 09:36:28 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-11 14:12:44 +0700 (Mon, 11 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Total.js Detection");

  script_tag(name:"summary", value:"Detection of Total.js.

The script sends a connection request to the server and attempts to detect Total.js and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.totaljs.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

port = get_http_port(default: 80);

banner = get_http_banner(port: port);

if (egrep(pattern: "X-Powered-By: total.js", string: banner, icase: TRUE)) {
  version = "unknown";

  # X-Powered-By: total.js v1.6.1
  vers = eregmatch(pattern: "X-Powered-By: total.js v([0-9.]+)", string: banner, icase: TRUE);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "totaljs/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:totaljs:total.js:");
  if (!cpe)
    cpe = "cpe:/a:totaljs:total.js";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Total.js", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
