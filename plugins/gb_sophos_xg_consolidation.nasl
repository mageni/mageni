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
  script_oid("1.3.6.1.4.1.25623.1.0.147867");
  script_version("2022-03-31T04:03:17+0000");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-29 08:58:01 +0000 (Tue, 29 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sophos XG Firewall Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Sophos XG Firewall detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_sophos_xg_admin_http_detect.nasl",
                      "gb_sophos_xg_user_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_sophos_xg_ssh_login_detect.nasl",
                        "gsf/gb_sophos_xg_snmp_detect.nasl");
  script_mandatory_keys("sophos/xg_firewall/detected");

  script_xref(name:"URL", value:"https://www.sophos.com/en-us/products/next-gen-firewall");

  exit(0);
}

if (!get_kb_item("sophos/xg_firewall/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "snmp", "http-admin", "http-user")) {
  version_list = get_kb_list("sophos/xg_firewall/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_name = "Sophos Firewall Operating System (SFOS)";
hw_name = "Sophos XG Firewall";

cpe_version = str_replace(string: detected_version, find: " ", replace: "");
cpe_version = str_replace(string: cpe_version, find: "Build", replace: "");
cpe_version = ereg_replace(string: cpe_version, pattern: "MR-[0-9]", replace: "");
cpe_version = str_replace(string: cpe_version, find: "-", replace: ".");
os_cpe1 = build_cpe(value: cpe_version, exp: "^([0-9.]+)", base: "cpe:/o:sophos:sfos:");
# nb: Some older CVEs in the NVD are still using this OS CPE:
os_cpe2 = build_cpe(value: cpe_version, exp: "^([0-9.]+)", base: "cpe:/o:sophos:xg_firewall_firmware:");
if (!os_cpe1) {
  os_cpe1 = "cpe:/o:sophos:sfos";
  os_cpe2 = "cpe:/o:sophos:xg_firewall_firmware";
}

hw_cpe = "cpe:/h:sophos:xg_firewall";

if (admin_ports = get_kb_list("sophos/xg_firewall/http-admin/port")) {
  foreach port (admin_ports) {
    extra += 'HTTP(s) admin portal on port ' + port + '/tcp\n';

    concluded = get_kb_item("sophos/xg_firewall/http-admin/" + port + "/concluded");
    concludedUrl = get_kb_item("sophos/xg_firewall/http-admin/" + port + "/concludedUrl");

    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    if (concludedUrl)
      extra += '  Concluded from version/product identification location: ' + concludedUrl + '\n';

    register_product(cpe: os_cpe1, location: location, port: port, service: "www");
    register_product(cpe: os_cpe2, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (admin_ports = get_kb_list("sophos/xg_firewall/http-user/port")) {
  foreach port (admin_ports) {
    extra += 'HTTP(s) user portal on port ' + port + '/tcp\n';

    concluded = get_kb_item("sophos/xg_firewall/http-user/" + port + "/concluded");
    concludedUrl = get_kb_item("sophos/xg_firewall/http-user/" + port + "/concludedUrl");

    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    if (concludedUrl)
      extra += '  Concluded from version/product identification location: ' + concludedUrl + '\n';

    register_product(cpe: os_cpe1, location: location, port: port, service: "www");
    register_product(cpe: os_cpe2, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("sophos/xg_firewall/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concludedOS = get_kb_item("sophos/xg_firewall/snmp/" + port + "/concludedOS");
    if (concludedOS) {
      concludedOSOID = get_kb_item("sophos/xg_firewall/snmp/" + port + "/concludedOSOID");
      extra += '  OS concluded from "' + concludedOS + '" via OID: ' + concludedOSOID + '\n';
    }

    concludedVers = get_kb_item("sophos/xg_firewall/snmp/" + port + "/concludedVers");
    if (concludedVers) {
      concludedVersOID = get_kb_item("sophos/xg_firewall/snmp/" + port + "/concludedVersOID");
      extra += '  Version concluded from "' + concludedVers + '" via OID: ' + concludedVersOID + '\n';
    }

    register_product(cpe: os_cpe1, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe2, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_ports = get_kb_list("sophos/xg_firewall/ssh-login/port")) {
  foreach port (ssh_ports) {
    extra += 'SSH login on port ' + port + '/tcp\n';

    concluded = get_kb_item("sophos/xg_firewall/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe1, location: location, port: port, service: "ssh-login");
    register_product(cpe: os_cpe2, location: location, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

os_register_and_report(os: os_name, cpe: os_cpe1, runs_key: "unixoide",
                       desc: "Sophos XG Firewall Detection Consolidation");

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe1);
report += '\n\n';
report += build_detection_report(app: hw_name, install: location, cpe: hw_cpe, skip_version: TRUE);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
