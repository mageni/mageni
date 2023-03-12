# Copyright (C) 2023 Greenbone Networks GmbH
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

include("plugin_feed_info.inc");

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.149276");
  script_version("2023-02-16T10:08:32+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:08:32 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-15 07:47:16 +0000 (Wed, 15 Feb 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HPE OfficeConnect Switch Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_hpe_officeconnect_switch_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_hpe_officeconnect_switch_http_detect.nasl");
  script_mandatory_keys("hp/officeconnect/switch/detected");

  script_tag(name:"summary", value:"Consolidation of HPE OfficeConnect Switch detections.");

  script_xref(name:"URL", value:"https://www.hpe.com/us/en/networking/small-business-networking.html");

  exit(0);
}

if (!get_kb_item("hp/officeconnect/switch/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_model = "unknown";
detected_series = "unknown";
location = "/";

foreach source (make_list("snmp", "http")) {
  version_list = get_kb_list("hp/officeconnect/switch/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("hp/officeconnect/switch/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "hp/officeconnect/switch/model", value: detected_model);
      break;
    }
  }

  series_list = get_kb_list("hp/officeconnect/switch/" + source + "/*/series");
  foreach series (series_list) {
    if (series != "unknown" && detected_series == "unknown") {
      detected_series = series;
      set_kb_item(name: "hp/officeconnect/switch/series", value: detected_series);
      break;
    }
  }
}

if (detected_series != "unknown" && detected_model != "unknown") {
  os_name = "HPE OfficeConnect " + detected_series + " " + detected_model + " Firmware";
  hw_name = "HPE OfficeConnect " + detected_series + " " + detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:hpe:officeconnect_" + tolower(detected_series) + "_" +
                           tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:hpe:officeconnect_" + tolower(detected_series) + "_" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:hpe:officeconnect_" + tolower(detected_series) + "_" + tolower(detected_model);
} else if (detected_series != "unknown") {
  os_name = "HPE OfficeConnect " + detected_series + " Firmware";
  hw_name = "HPE OfficeConnect " + detected_series + " Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:hpe:officeconnect_" + tolower(detected_series) + "_firmware:");
  if (!os_cpe)
    cpe = "cpe:/o:hpe:officeconnect_" + tolower(detected_series) + "_firmware";

  hw_cpe = "cpe:/h:hpe:officeconnect_" + tolower(detected_series);
} else if (detected_model != "unknown") {
  os_name = "HPE OfficeConnect " + detected_model + " Firmware";
  hw_name = "HPE OfficeConnect " + detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:hpe:officeconnect_" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:hpe:officeconnect_" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:hpe:officeconnect_" + tolower(detected_model);
} else {
  os_name = "HPE OfficeConnect Firmware";
  hw_name = "HPE OfficeConnect Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:hpe:officeconnect_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:hpe:officeconnect_firmware";

  hw_cpe = "cpe:/h:hpe:officeconnect";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "HPE OfficeConnect Switch Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("hp/officeconnect/switch/http/port")) {
  foreach port (http_ports) {
    extra = "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("hp/officeconnect/switch/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    concludedUrl = get_kb_item("hp/officeconnect/switch/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += '  Concluded from version/product identification location: ' + concludedUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("hp/officeconnect/switch/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("hp/officeconnect/switch/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  SNMP Banner:" + concluded + '\n';

    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
