# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.147819");
  script_version("2022-03-22T09:17:22+0000");
  script_tag(name:"last_modification", value:"2022-03-22 11:26:02 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-22 01:46:18 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Twisted Web Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Twisted Web.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("twistedweb/banner");

  script_xref(name:"URL", value:"https://twistedmatrix.com/trac/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

banner = http_get_remote_headers(port: port);

if (!concl = egrep(string: banner, pattern: "^Server\s*:.*TwistedWeb/", icase: TRUE))
  exit(0);

version = "unknown";

set_kb_item(name: "twistedweb/detected", value: TRUE);
set_kb_item(name: "twistedweb/http/detected", value: TRUE);

# Server: TwistedWeb/20.3.0dev0
# Server: Twisted/13.0.0 TwistedWeb/9.0.0
# Server: TwistedWeb/16.4.0
# Server: Twisted/13.2.0 TwistedWeb/[twisted.web2, version 8.1.0]
vers = eregmatch(pattern: "TwistedWeb/([twisted.web2, version )?([0-9a-z.]+)", string: concl, icase: TRUE);
if (!isnull(vers[1]))
  version = vers[1];

cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:twistedmatrix:twisted:");
if (!cpe)
  cpe = "cpe:/a:twistedmatrix:twisted";

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "Twisted Web", version: version, install: "/",
                                         cpe: cpe, concluded: concl),
            port: port);

exit(0);
