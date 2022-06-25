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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147702");
  script_version("2022-03-01T03:54:49+0000");
  script_tag(name:"last_modification", value:"2022-03-03 11:27:55 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-02-25 07:12:54 +0000 (Fri, 25 Feb 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WatchGuard Firebox Appliance Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of WatchGuard Firebox appliance detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_watchguard_firebox_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_watchguard_firebox_ssh_login_detect.nasl",
                        "gsf/gb_watchguard_firebox_snmp_detect.nasl");
  script_mandatory_keys("watchguard/firebox/detected");

  script_xref(name:"URL", value:"https://www.watchguard.com/wgrd-products/firewall-appliances");

  exit(0);
}

if (!get_kb_item("watchguard/firebox/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "snmp", "http")) {
  model_list = get_kb_list("watchguard/firebox/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  version_list = get_kb_list("watchguard/firebox/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_name = "WatchGuard ";
hw_name = os_name;

if (detected_model != "unknown") {
  os_name += detected_model + " Firmware";
  hw_name += detected_model;

  cpe_model = tolower(str_replace(string: detected_model, find: " ", replace: "_"));
  hw_cpe = "cpe:/h:watchguard:" + cpe_model;
} else {
  os_name += "Unknown Model Firmware";
  hw_name += "Unknown Model";

  hw_cpe = "cpe:/h:watchguard:firebox";
}

os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:watchguard:fireware:");
if (!os_cpe)
  os_cpe = "cpe:/o:watchguard:fireware";

if (http_ports = get_kb_list("watchguard/firebox/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concludedUrl = get_kb_item("watchguard/firebox/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += '  Concluded from version/product identification location: ' + concludedUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("watchguard/firebox/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item("watchguard/firebox/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from SNMP banner "' + concluded + '"';

    concludedVers = get_kb_item("watchguard/firebox/snmp/" + port + "/concludedVers");
    if (concludedVers) {
      concludedVersOID = get_kb_item("watchguard/firebox/snmp/" + port + "/concludedVersOID");
      extra += '  Version concluded from "' + concludedVers + '" via OID: ' + concludedVersOID + '\n';
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_ports = get_kb_list("watchguard/firebox/ssh-login/port")) {
  foreach port (ssh_ports) {
    extra += 'SSH login on port ' + port + '/tcp\n';

    concluded = get_kb_item("watchguard/firebox/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "WatchGuard Firebox Appliance Detection Consolidation");

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, install: location, cpe: hw_cpe, skip_version: TRUE);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
