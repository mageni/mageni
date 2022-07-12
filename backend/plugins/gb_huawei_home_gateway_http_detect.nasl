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
  script_oid("1.3.6.1.4.1.25623.1.0.146155");
  script_version("2021-06-21T09:27:32+0000");
  script_tag(name:"last_modification", value:"2021-06-21 10:10:42 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-21 06:07:35 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei Home Gateway Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Huawei Home Gateway devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://consumer.huawei.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ('<div id="huaweilogo"' >< res && "Home Gateway" >< res && "js/device_info.js") {
  version = "unknown";
  hw_version = "unknown";
  location = "/";

  os_name = "Huawei Home Gateway ";
  hw_name = os_name;

  set_kb_item(name: "huawei/home_gateway/detected", value: TRUE);
  set_kb_item(name: "huawei/home_gateway/http/detected", value: TRUE);

  url = "/api/system/deviceinfo";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # while(1); /*{"DeviceName":"HG659","SerialNumber":"J3N8W16519004880","ManufacturerOUI":"00E0FC","UpTime":52146,"SoftwareVersion":"V100R001C01B011","HardwareVersion":"VER.B"}*/

  vers = eregmatch(pattern: '"SoftwareVersion":"([^"]+)"', string: res);
  if (!isnull(vers[1])) {
    concluded = vers[0];
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  mod = eregmatch(pattern: '"DeviceName":"([^"]+)"', string: res);
  if (!isnull(mod[1])) {
    if (concluded)
      concluded += '\n';
    concluded += mod[0];
    model = mod[1];
    os_name += mod[1] + " Firmware";
    hw_name += mod[1];
    cpe_model = tolower(str_replace(string: mod[1], find: " ", replace: "_"));

    os_cpe = build_cpe(value: tolower(version), exp: "^([a-z0-9]+)",
                       base: "cpe:/o:huawei:" + cpe_model + "_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:huawei:" + cpe_model + "_firmware";

    hw_cpe = "cpe:/h:huawei:" + cpe_model;
  } else {
    os_name += " Firmware";
    hw_name += " Unknown Model";

    os_cpe = build_cpe(value: tolower(version), exp: "^([a-z0-9]+)", base: "cpe:/o:huawei:home_gateway_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:huawei:home_gateway_firmware";

    hw_cpe = "cpe:/h:huawei:home_gateway";
  }

  hw_ver = eregmatch(pattern: '"HardwareVersion":"VER\\.([^"]+)"', string: res);
  if (hw_ver) {
    if (concluded)
      concluded += '\n';
    concluded += hw_ver[0];
    hw_version = hw_ver[1];
    hw_cpe += ":" + tolower(hw_version);
  }

  os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                         desc: "Huawei Home Gateway Detection (HTTP)");

  register_product(cpe: os_cpe, location: location, port: port, service: "www");
  register_product(cpe: hw_cpe, location: location, port: port, service: "www");

  report  = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe);
  report += '\n\n';
  report += build_detection_report(app: hw_name, version: hw_version, install: location, cpe: hw_cpe);

  if (concluded)
    report += '\n\nConcluded from version/product identification result:\n' + concluded;

  if (concUrl)
    report += '\n\nConcluded from version/product identification location:\n' + concUrl;

  log_message(port: port, data: report);
}

exit(0);
