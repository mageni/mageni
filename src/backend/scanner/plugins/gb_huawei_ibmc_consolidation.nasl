# Copyright (C) 2020 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144459");
  script_version("2020-08-26T13:46:49+0000");
  script_tag(name:"last_modification", value:"2020-08-27 11:59:41 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-25 08:08:42 +0000 (Tue, 25 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei iBMC Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Huawei iBMC detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_huawei_ibmc_upnp_detect.nasl", "gb_huawei_ibmc_http_detect.nasl");
  script_mandatory_keys("huawei/ibmc/detected");

  script_xref(name:"URL", value:"https://e.huawei.com/en/products/servers/accessories/ibmc");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("huawei/ibmc/detected"))
  exit(0);

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source (make_list("upnp", "http")) {
  version_list = get_kb_list("huawei/ibmc/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("huawei/ibmc/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "huawei/server/model", value: detected_model);
      break;
    }
  }
}

if (detected_model != "unknown")
  os_name = "Huawei iBMC Firmware on " + detected_model;
else
  os_name = "Huawei iBMC Firmware";

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:huawei:ibmc_firmware:");
if (!cpe)
  cpe = "cpe:/o:huawei:ibmc_firmware";

register_and_report_os(os: os_name, cpe: cpe, desc: "Huawei iBMC Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("huawei/ibmc/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("huawei/ibmc/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    concUrl = get_kb_item("huawei/ibmc/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (upnp_ports = get_kb_list("huawei/ibmc/upnp/port")) {
  foreach port (upnp_ports) {
    extra += 'UPnP on port ' + port + '/udp\n';

    concluded = get_kb_item("huawei/ibmc/upnp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "upnp", proto: "udp");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
