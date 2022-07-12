# Copyright (C) 2020 Greenbone Networks GmbH
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

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143539");
  script_version("2020-02-21T08:38:10+0000");
  script_tag(name:"last_modification", value:"2020-02-21 11:05:25 +0000 (Fri, 21 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-20 06:51:05 +0000 (Thu, 20 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SonicWall / Dell SonicWALL SRA / SMA Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected SonicWall / Dell SonicWALL
  Secure Mobile Access (SMA) and Secure Remote Access (SRA) including the version number and series.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_dell_sonicwall_sma_detection.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_dell_sonicwall_sma_sra_http_detect.nasl");

  script_mandatory_keys("sonicwall/sra_sma/detected");

  script_xref(name:"URL", value:"https://www.sonicwall.com/products/remote-access/remote-access-appliances/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("sonicwall/sra_sma/detected"))
  exit(0);

detected_product = "unknown";
detected_series = "unknown";
detected_version = "unknown";

foreach source (make_list("snmp", "http")) {
  product_list = get_kb_list("sonicwall/sra_sma/" + source + "/*/product");
  foreach product (product_list) {
    if (product != "unknown" && detected_product == "unknown")
      detected_product = product;
      break;
  }

  series_list = get_kb_list("sonicwall/sra_sma/" + source + "/*/series");
  foreach series (series_list) {
    if (series != "unknown" && detected_series == "unknown")
      detected_series = series;
      break;
  }

  version_list = get_kb_list("sonicwall/sra_sma/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown")
      detected_version = version;
      break;
  }
}

name = "SonicWall ";
base_cpe = "cpe:/o:sonicwall:";

if (detected_product != "unknown") {
  name += detected_product + " ";
  base_cpe += tolower(detected_product);

  if (detected_series != "unknown") {
    os_name = name + detected_series;
    base_cpe += "_" + tolower(str_replace(string: detected_series, find: " ", replace: "_"));
    if (detected_series != "Virtual Appliance")
      hw_cpe = "cpe:/h:sonicwall:" + tolower(detected_product) + "_" +
               tolower(str_replace(string: detected_series, find: " ", replace: "_"));
    else
      app_cpe = "cpe:/a:sonicwall:" + tolower(detected_product) + "_" +
                tolower(str_replace(string: detected_series, find: " ", replace: "_"));
  } else {
    os_name = name + "Unknown Series";
  }
} else {
  os_name += "SMA / SRA";
  base_cpe += "sma_sra";
}

os_cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9a-z.-]+)", base: base_cpe + "_firmware:");
if (!os_cpe)
  os_cpe = base_cpe + "_firmware";

location = "/";

if (http_ports = get_kb_list("sonicwall/sra_sma/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("sonicwall/sra_sma/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "www");
    if (app_cpe)
      register_product(cpe: app_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("sonicwall/sra_sma/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item("sonicwall/sra_sma/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from SNMP SysDesc: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
    if (app_cpe)
      register_product(cpe: app_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

register_and_report_os(os: os_name + " Firmware", cpe: os_cpe, desc: "SonicWall / Dell SonicWALL SRA / SMA Detection Consolidation",
                       runs_key: "unixoide");

report = build_detection_report(app: os_name + " Firmware", version: detected_version, install: location, cpe: os_cpe);
if (hw_cpe)
  report += '\n\n' + build_detection_report(app: os_name + " Appliance", skip_version: TRUE, install: location,
                                            cpe: hw_cpe);

if (app_cpe)
  report += '\n\n' + build_detection_report(app: os_name, skip_version: TRUE, install: location,
                                            cpe: app_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\r\n' + extra;
}

if (report)
  log_message(port: 0, data: report);

exit(0);
