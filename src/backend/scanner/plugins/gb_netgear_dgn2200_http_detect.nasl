# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107228");
  script_version("2021-07-02T07:45:35+0000");
  script_tag(name:"last_modification", value:"2021-07-02 10:34:13 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"creation_date", value:"2017-06-28 14:43:29 +0200 (Wed, 28 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NETGEAR DGN2200 Router Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of NETGEAR DGN 2200 routers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("DGN2200/banner");

  script_xref(name:"URL", value:"https://www.netgear.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

res = http_get_cache(port: port, item: "/");

if ('WWW-Authenticate: Basic realm="NETGEAR DGN2200' >< res) {
  set_kb_item(name: "netgear_dgn2200/detected", value: TRUE);
  set_kb_item(name: "netgear/router/detected", value: TRUE);

  version = "unknown";

  # keeping this in, although the version can only be obtained via authentication right now.
  ver = eregmatch(pattern: 'NETGEAR DGN2200v([0-9])', string: res);
  if (!isnull(ver[1]))
    version = ver[1];

  os_cpe = build_cpe(value: version, exp: "^([0-9]+)", base: "cpe:/o:netgear:dgn2200_firmware:");
  if (!cpe)
    os_cpe = "cpe:/o:netgear:dgn2200_firmware";

  hw_cpe = "cpe:/h:netgear:dgn2200";

  register_product(cpe: os_cpe, location: "/", port: port, service: "www");
  register_product(cpe: os_cpe, location: "/", port: port, service: "www");

  os_register_and_report(os: "NETGEAR DGN2200 Firmware", cpe: os_cpe, runs_key: "unixoide",
                         desc: "NETGEAR DGN2200 Router Detection (HTTP)");

  report = build_detection_report(app: "NETGEAR DGN2200 Firmware", version: version, install: "/",
                                  cpe: os_cpe, concluded: ver[0]);
  report += '\n\n' + build_detection_report(app: "NETGEAR DGN2200", install: "/", cpe: hw_cpe,
                                            skip_version: TRUE);

  log_message(port: port, data: report);
}

exit(0);
