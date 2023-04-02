# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107300");
  script_version("2023-03-14T10:10:15+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-14 10:10:15 +0000 (Tue, 14 Mar 2023)");
  script_tag(name:"creation_date", value:"2018-02-15 14:47:17 +0100 (Thu, 15 Feb 2018)");

  script_name("TrendNet Router Devices Detection (HTTP)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of TrendNet router devices.");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

url = "/";
res = http_get_cache(port: port, item: url);

if ("Login to the" >< res && ("<title>TRENDNET | WIRELESS N ROUTER </title>" >< res || "<title>TRENDNET | WIRELESS N GIGABIT ROUTER </title>" >< res)) {

  model = "unknown";
  version = "unknown";
  install = url;

  router = eregmatch(pattern: "[Ss]erver\s*:\s*Linux, HTTP/1.., (TEW-[0-9a-zA-Z]+) Ver ([0-9.]+)", string: res);
  if (!isnull(router[1]))
    model = router[1];

  if (!isnull(router[2]))
    version = router[2];

  set_kb_item(name: "trendnet/router_device/detected", value: TRUE);
  set_kb_item(name: "trendnet/router_device/http/detected", value: TRUE);
  set_kb_item(name: "trendnet/router_device/model", value: model);
  set_kb_item(name: "trendnet/router_device/version", value: version);

  # TBD: Register the firmware as a separate OS CPE?

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:trendnet:" + tolower(model) + ":");
  if (!cpe)
    cpe = "cpe:/h:trendnet:" + tolower(model);

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "TrendNet Router " + model,
                                           version: version,
                                           install: install,
                                           cpe: cpe,
                                           concluded: router),
              port: port);
}

exit(0);
