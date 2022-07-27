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
  script_oid("1.3.6.1.4.1.25623.1.0.143255");
  script_version("2019-12-17T07:47:12+0000");
  script_tag(name:"last_modification", value:"2019-12-17 07:47:12 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-16 07:45:56 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Inim SmartLAN Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Inim SmartLAN devices.

  HTTP based detection of Inim SmartLAN devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

res = http_get_cache(port: port, item: "/");

if ("<title>SmartLAN" >!< res || "smartlang.appcache" >!< res)
  exit(0);

set_kb_item(name: "inim/smartlan/detected", value: TRUE);
set_kb_item(name: "inim/smartlan/http/detected", value: TRUE);
set_kb_item(name: "inim/smartlan/http/port", value: port);

version = "unknown";

url = "/version.html";
res = http_get_cache(port: port, item: url);

# SmartLiving 6.04 00515
# <br><br>SmartLAN/G v. 6.11
vers = eregmatch(pattern: "SmartLAN[^v]+v\. ([0-9.]+)", string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "inim/smartlan/http/" + port + "/concluded", value: vers[0]);
  set_kb_item(name: "inim/smartlan/http/" + port + "/concUrl",
              value: report_vuln_url(port: port, url: url, url_only: TRUE));
}

set_kb_item(name: "inim/smartlan/http/" + port + "/version", value: version);

exit(0);
