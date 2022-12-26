# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113576");
  script_version("2022-12-06T10:11:16+0000");
  script_tag(name:"last_modification", value:"2022-12-06 10:11:16 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"creation_date", value:"2019-11-22 15:39:55 +0200 (Fri, 22 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sambar Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("sambar/banner");

  script_tag(name:"summary", value:"HTTP based detection of Sambar Server.");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);

if (banner =~ "Server\s*:\s*SAMBAR") {
  version = "unknown";

  set_kb_item(name: "sambar_server/detected", value: TRUE);
  set_kb_item(name: "sambar_server/http/detected", value: TRUE);

  # Server: sambar/5.1
  vers = eregmatch(string: banner, pattern: "Sambar[/ ]([0-9.]+)", icase: TRUE);
  if (!isnull(vers[1]))
    version = vers[1];

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:sambar:sambar_server:");
  if (!cpe)
    cpe = "cpe:/a:sambar:sambar_server";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Sambar Server", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);

  exit(0);
}

exit(0);
