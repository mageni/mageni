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
  script_oid("1.3.6.1.4.1.25623.1.0.144111");
  script_version("2020-06-16T12:51:32+0000");
  script_tag(name:"last_modification", value:"2020-06-17 08:59:13 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-16 03:46:25 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZNC Consolidation");

  script_tag(name:"summary", value:"Reports the ZNC version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_znc_http_detect.nasl", "gb_znc_irc_detect.nasl");
  script_mandatory_keys("znc/detected");

  script_xref(name:"URL", value:"https://wiki.znc.in/ZNC");

  exit(0);
}

if (!get_kb_item("znc/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("http", "irc")) {
  version_list = get_kb_list("znc/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9.]+)", base: "cpe:/a:znc:znc:");
if (!cpe)
  cpe = "cpe:/a:znc:znc";

if (http_ports = get_kb_list("znc/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';
    concluded = get_kb_item("znc/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (irc_ports = get_kb_list("znc/irc/port")) {
  foreach port (irc_ports) {
    extra += 'IRC on port + ' + port + '/tcp\n';
    concluded = get_kb_item("znc/irc/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "irc");
  }
}

report = build_detection_report(app: "ZNC", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
