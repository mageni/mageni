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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144170");
  script_version("2020-06-26T04:54:54+0000");
  script_tag(name:"last_modification", value:"2020-06-30 10:45:10 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-25 09:49:44 +0000 (Thu, 25 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Network Analysis Module Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_cisco_nam_ssh_login.nasl", "gb_cisco_nam_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cisco_nam_snmp_detect.nasl");
  script_mandatory_keys("cisco/nam/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco Network Analysis Module detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/cloud-systems-management/network-analysis-module-nam/index.html");

  exit(0);
}

if (!get_kb_item("cisco/nam/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
detected_patch = "No patch installed/detected";
location = "/";

foreach source (make_list("ssh-login", "http", "snmp")) {
  version_list = get_kb_list("cisco/nam/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  patch_list = get_kb_list("cisco/nam/" + source + "/*/patch");
  foreach patch (patch_list) {
    if (patch != "unknown" && detected_patch == "No patch installed/detected") {
      detected_patch = patch;
      set_kb_item(name: "cisco/nam/patch", value: detected_patch);
      break;
    }
  }
}

cpe = build_cpe(value: tolower(version), exp: "([0-9a-z.]+)", base: "cpe:/a:cisco:prime_network_analysis_module:");
if (!cpe)
  cpe = "cpe:/a:cisco:prime_network_analysis_module";

register_and_report_os(os: "Cisco NAM", cpe: "cpe:/o:cisco:prime_network_analysis_module_firmware",
                       desc: "Cisco Network Analysis Module Detection Consolidation", runs_key: "unixoide");

if (ssh_login_ports = get_kb_list("cisco/nam/ssh-login/port")) {
  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    concluded = get_kb_item("cisco/nam/ssh-login/" + port + "/concluded");
    extra += '  Port:                           ' + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded from version/product\n';
      extra += '  identification result:          ' + concluded;

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

if (http_ports = get_kb_list("cisco/nam/http/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {
    concluded = get_kb_item("cisco/nam/http/" + port + "/concluded");
    extra += '  Port:                           ' + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded from:                 ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("cisco/nam/snmp/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over SNMP:\n';

  foreach port (snmp_ports) {
    concluded = get_kb_item("cisco/nam/snmp/" + port + "/concluded");
    extra += 'Port                              ' + port + '/udp\n';
    if (concluded)
      extra += '  SNMP Banner:                    ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report = build_detection_report(app: "Cisco Network Analysis Module",
                                version: detected_version, cpe: cpe, install: location, patch: detected_patch);

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
