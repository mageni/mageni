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
  script_oid("1.3.6.1.4.1.25623.1.0.148591");
  script_version("2022-08-16T10:20:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-16 10:20:04 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-12 06:26:53 +0000 (Fri, 12 Aug 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ARRIS Router Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP detection of ARRIS routers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/cgi-bin/home.ha";

res = http_get_cache(port: port, item: url);

if ("ARRIS Enterprises" >< res && 'class="cssbtn btnspacer"' >< res) {
  version = "unknown";
  model = "unknown";
  location = "/";

  # <div id="version">NVG443B Version: 9.3.0h3d36</div>
  tmp = eregmatch(pattern: '"version">([^<]+)<', string: res);
  if (!isnull(tmp[1])) {
    mod_vers = split(tmp[1], sep: " ", keep: FALSE);
    if (!isnull(mod_vers[0]))
      model = mod_vers[0];

    if (!isnull(mod_vers[2]))
      version = mod_vers[2];
  }

  set_kb_item(name: "arris/router/detected", value: TRUE);
  set_kb_item(name: "arris/router/http/detected", value: TRUE);

  if (model != "unknown") {
    os_name = "ARRIS " + model + " Firmware";
    hw_name = "ARRIS " + model;

    os_cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)",
                       base: "cpe:/o:arris:" + tolower(model) + "_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:arris:" + tolower(model) + "_firmware";

    hw_cpe = "cpe:/h:arris:" + tolower(model);
  } else {
    os_name = "ARRIS Unknown Model Firmware";
    hw_name = "ARRIS Unknown Model";

    os_cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/o:arris:router_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:arris:router_firmware";

    hw_cpe = "cpe:/h:arris:router";
  }

  os_register_and_report(os: os_name, cpe: os_cpe, desc: "ARRIS Router Detection (HTTP)",
                         runs_key: "unixoide");

  register_product(cpe: os_cpe, location: location, port: port, service: "www");
  register_product(cpe: hw_cpe, location: location, port: port, service: "www");

  report  = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe,
                                   concluded: tmp[0],
                                   concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  report += '\n\n';
  report += build_detection_report(app: hw_name, install: location, cpe: hw_cpe, skip_version: TRUE);

  log_message(port: 0, data: report);
}

exit(0);
