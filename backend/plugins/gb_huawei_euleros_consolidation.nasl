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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143355");
  script_version("2020-01-16T09:51:04+0000");
  script_tag(name:"last_modification", value:"2020-01-16 09:51:04 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-15 02:15:18 +0000 (Wed, 15 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei EulerOS Detection Consolidation");

  script_tag(name:"summary", value:"Reports the Huawei EulerOS version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_huawei_euleros_ssh_detect.nasl", "gb_huawei_euleros_snmp_detect.nasl");
  script_mandatory_keys("huawei/euleros/detected");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros");

  exit(0);
}

if (!get_kb_item("huawei/euleros/detected"))
  exit(0);

include("host_details.inc");

detected_version = "unknown";
detected_sp      = "unknown";

foreach source (make_list("ssh-login", "snmp")) {
  version_list = get_kb_list("huawei/euleros/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      set_kb_item(name: "huawei/euleros/version", value: version);
      break;
    }
  }

  sp_list = get_kb_list("huawei/euleros/" + source + "/*/sp");
  foreach service_pack (sp_list) {
    if (service_pack && detected_sp == "unknown") {
      detected_sp = service_pack;
      set_kb_item(name: "huawei/euleros/sp", value: service_pack);
      break;
    }
  }
}

os_cpe = "cpe:/o:huawei:euleros";
os_key = "EULEROS";

if (detected_version != "unknown") {
  os_cpe += ":" + detected_version;
  os_key += detected_version;

  if (detected_sp != "unknown") {
    os_cpe += ":sp" + detected_sp;
    os_key += "SP" + detected_sp;
    service_pack = "SP" + detected_sp;
  } else {
    os_cpe += ":sp0";
    os_key += "SP0";
  }
}

register_and_report_os(os: "Huawei EulerOS", cpe: os_cpe, desc: "Huawei EulerOS Detection Consolidation",
                       runs_key: "unixoide");

location = "/";

if (ssh_ports = get_kb_list("huawei/euleros/ssh-login/port")) {
  set_kb_item(name: "ssh/login/release", value: os_key);

  foreach port (ssh_ports) {
    extra += "SSH on port " + port + '/tcp\n';

    concluded = get_kb_item("huawei/euleros/ssh-login/" + port + "/concluded");
    if (concluded) {
      extra += "  Concluded from version/product identification result: " + concluded + '\n';
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
  }
}

if (snmp_ports = get_kb_list("huawei/euleros/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("huawei/euleros/snmp/" + port + "/concluded");
    concludedOID = get_kb_item("huawei/euleros/snmp/" + port + "/concludedOID");
    if (concluded && concludedOID) {
      extra += '  Concluded from ' + concluded + ' via OID: ' + concludedOID + '\n';
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report = build_detection_report(app: "Huawei EulerOS", version: detected_version, patch: service_pack,
                                install: location, cpe: os_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
