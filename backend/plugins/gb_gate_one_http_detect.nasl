# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.146034");
  script_version("2021-05-28T07:20:53+0000");
  script_tag(name:"last_modification", value:"2021-06-03 10:25:40 +0000 (Thu, 03 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-28 05:50:58 +0000 (Fri, 28 May 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Gate One Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Gate One.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://liftoff.github.io/GateOne/index.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

# nb: Don't use http_get_cache() as we need a current cookie
req = http_get(port: port, item: "/auth?next=%2F");
res = http_keepalive_send_recv(port: port, data: req);

if ("gateone_user" >!< res)
  exit(0);

cookie = http_get_cookie_from_header(buf: res, pattern: "(gateone_user=[^;]+)");
if (isnull(cookie))
  exit(0);

headers = make_array("Cookie", cookie);

url = "/";

req = http_get_req(port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if ('id="gateone"' >< res && "GateOne.init()" >< res) {
  version = "unknown";

  set_kb_item(name: "liftoffsoftware/gateone/detected", value: TRUE);
  set_kb_item(name: "liftoffsoftware/gateone/http/detected", value: TRUE);

  cpe = "cpe:/a:liftoffsoftware:gateone";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  os_register_and_report(os: "Linux/Unix", cpe:"cpe:/o:linux:kernel", runs_key: "unixoide",
                         desc: "Gate One Detection (HTTP)");

  log_message(data: build_detection_report(app: "Gate One", version: version, install: "/", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
