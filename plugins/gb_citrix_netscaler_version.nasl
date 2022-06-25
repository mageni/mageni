###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_netscaler_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Citrix NetScaler Detection Consolidation
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Adrian Steins <adrian.steins@greenbone.net>
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105271");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-11 16:54:59 +0200 (Mon, 11 May 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix NetScaler Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected Citrix Netscaler including the version number
and exposed services.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_netscaler_ssh_detect.nasl", "gb_netscaler_snmp_detect.nasl", "netscaler_web_detect.nasl");
  script_mandatory_keys("citrix_netscaler/detected");

  script_xref(name:"URL", value:"https://www.citrix.com/products/netscaler-adc/");

  exit(0);
}

include("host_details.inc");

detected_version = "unknown";

foreach source (make_list("ssh", "snmp", "http")) {
  if (detected_version != "unknown")
    break;

  version_list = get_kb_list("citrix_netscaler/" + source + "/*/version");
  foreach version (version_list) {
    if (version && detected_version == "unknown") {
      detected_version = version;
      set_kb_item(name: "citrix_netscaler/version", value: version);
    }
  }
}

# TODO: Set a correct CPE based on the Netscaler Product like e.g. NetScaler Gateway on /epa/epa.html
# See e.g. https://nvd.nist.gov/products/cpe/search/results?keyword=cpe%3a%2fo%3acitrix*&status=FINAL&orderBy=CPEURI&namingFormat=2.2&startIndex=0
if (detected_version != "unknown") {
  cpe    = "cpe:/a:citrix:netscaler:" + detected_version;
  os_cpe = "cpe:/o:citrix:netscaler:" + detected_version;
} else {
  cpe    = "cpe:/a:citrix:netscaler";
  os_cpe = "cpe:/o:citrix:netscaler";
}

# SSH
if (ssh_ports = get_kb_list("citrix_netscaler/ssh/port")) {
  foreach port (ssh_ports) {
    extra += "SSH on port " + port + '/tcp\n';

    concluded = get_kb_item("citrix_netscaler/ssh/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from: ' + concluded + '\n';

    register_product(cpe: cpe, location: port + '/tcp', port: port, service: "ssh");
  }
}

# SNMP
if (snmp_ports = get_kb_list("citrix_netscaler/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("citrix_netscaler/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from SNMP SysDesc: ' + concluded + '\n';

    register_product(cpe: cpe, location: port + '/udp', port: port, service: "snmp", proto: "udp");
  }
}

# HTTP
if (http_ports = get_kb_list("citrix_netscaler/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(S) on port " + port + '/tcp\n';

    concluded = get_kb_item("citrix_netscaler/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from: ' + concluded + '\n';
    concUrl = get_kb_item("citrix_netscaler/http/" + port + "/concUrl");
    if (concUrl)
      extra += '  Concluded from version identification location: ' + concUrl + '\n';
    detectUrl = get_kb_item("citrix_netscaler/http/" + port + "/detectUrl");
      extra += '  Detected URL: ' + detectUrl + '\n';

    register_product(cpe: cpe, location: port + '/tcp', port: port, service: "www");
  }
}

register_and_report_os(os: "Citrix NetScaler OS", cpe: os_cpe, desc: "Citrix NetScaler Detection Consolidation", runs_key: "unixoide");

enh_build = get_kb_item("citrix_netscaler/enhanced_build");
if (enh_build)
  enhanced = 'Enhanced Build\n';

report = build_detection_report(app: "Citrix NetScaler", version: version, install: "/", cpe: cpe,
                                extra: enhanced);
if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
