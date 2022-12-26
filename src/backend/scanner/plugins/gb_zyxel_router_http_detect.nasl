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
  script_oid("1.3.6.1.4.1.25623.1.0.149029");
  script_version("2022-12-19T07:28:58+0000");
  script_tag(name:"last_modification", value:"2022-12-19 07:28:58 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-19 05:32:09 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zyxel Router / Gateway Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Zyxel Router / Gateway devices.");

  script_xref(name:"URL", value:"https://www.zyxel.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/";

res = http_get_cache(port: port, item: url);

if ("'title'>.::Welcome to the Web-Based Configurator::." >< res && "zyxelhelp.js" >< res) {
  model = "unknown";
  version = "unknown";
  install = "/";
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "zyxel/router/detected", value: TRUE);
  set_kb_item(name: "zyxel/router/http/detected", value: TRUE);

  # id="MODEL_NAME" value="VMG1312-T20B"
  # id="MODEL_NAME" value="PMG5317-T20A"
  mod = eregmatch(pattern: 'id="MODEL_NAME"\\s+value="([^"]+)"', string: res);
  if (!isnull(mod[1]))
    model = mod[1];

  # id="FIRMWARE_VIRSION" value="V5.30(ABUA.0)b6"
  # id="FIRMWARE_VIRSION" value="V5.21(ABCI.6)C0"
  vers = eregmatch(pattern: 'id="FIRMWARE_VIRSION"\\s+value="V([^"]+)"', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  if (model != "unknown") {
    os_name = "Zyxel " + model + " Firmware";
    hw_name = "Zyxel " + model;

    os_cpe = build_cpe(value: version, exp: "^([0-9a-zA-Z\(\).]+)",
                       base: "cpe:/o:zyxel:" + tolower(model) + "_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:zyxel:" + tolower(model) + "_firmware";

    hw_cpe = "cpe:/h:zyxel:" + tolower(model);
  } else {
    os_name = "Zyxel Router / Gateway Firmware";
    hw_name = "Zyxel Router / Gateway Unknown Model";

    os_cpe = build_cpe(value: version, exp: "^([0-9a-zA-Z\(\).]+)", base: "cpe:/o:zyxel:router_firmware:");
    if (!cpe)
      os_cpe = "cpe:/o:zyxel:router_firmware";

    hw_cpe = "cpe:/h:zyxel:router";
  }

  os_register_and_report(os: os_name , cpe: os_cpe, banner_type: "Zyxel Router / Gateway Login Page",
                         port: port, desc: "Zyxel Router / Gateway Detection (HTTP)", runs_key: "unixoide" );

  register_product(cpe: os_cpe, location: install, port: port, service: "www");
  register_product(cpe: hw_cpe, location: install, port: port, service: "www");

  report = build_detection_report(app: os_name, version: version, install: install, cpe: os_cpe,
                                  concluded: vers[0], concludedUrl: concUrl);

  report += '\n\n';

  report += build_detection_report(app: hw_name, skip_version: TRUE, install: install, cpe: hw_cpe,
                                   concluded: mod[0], concludedUrl: concUrl);

  log_message(port: port, data: report);
}

exit(0);
