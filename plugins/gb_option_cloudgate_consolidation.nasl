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

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144128");
  script_version("2020-06-17T11:26:25+0000");
  script_tag(name:"last_modification", value:"2020-06-18 10:16:17 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-17 08:21:09 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Option GateCloud Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Option GateCloud device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_option_cloudgate_http_detect.nasl");
  if (FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_option_cloudgate_snmp_detect.nasl");
  script_mandatory_keys("option/cloudgate/detected");

  script_xref(name:"URL", value:"https://www.option.com/");

  exit(0);
}

if (!get_kb_item("option/cloudgate/detected"))
  exit(0);

include("host_details.inc");

detected_version = "unknown";
detected_model = "unknown";
location = "/";

os_name = "Option CloudGate Unknown Model Firmware";
hw_name = "Option CloudGate Unknown Model";

os_cpe = "cpe:/o:option:cloudgate_firmware";
hw_cpe = "cpe:/h:option:cloudgate";

register_and_report_os(os: os_name, cpe: os_cpe, desc: "Option GateCloud Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("option/cloudgate/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("option/cloudgate/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';
    concluded = get_kb_item("option/cloudgate/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP Banner: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
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
