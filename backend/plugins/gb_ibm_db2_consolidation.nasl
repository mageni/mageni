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
  script_oid("1.3.6.1.4.1.25623.1.0.143583");
  script_version("2020-03-11T02:02:56+0000");
  script_tag(name:"last_modification", value:"2020-03-11 02:02:56 +0000 (Wed, 11 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-05 08:14:29 +0000 (Thu, 05 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM Db2 Detection Consolidation");

  script_tag(name:"summary", value:"Reports the IBM Db2 version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ibm_db2_ssh_detect.nasl", "gb_ibm_db2_das_detect.nasl",
                      "gb_ibm_db2_smb_detect.nasl");
  if (FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_ibm_db2_drda_detect.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_xref(name:"URL", value:"https://www.ibm.com/analytics/db2");

  exit(0);
}

if (!get_kb_item("ibm/db2/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "smb", "drda", "das")) {
  version_list = get_kb_list("ibm/db2/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:db2:");
if (!cpe)
  cpe = "cpe:/a:ibm:db2";

if (ssh_login_ports = get_kb_list("ibm/db2/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += 'SSH-Login on port ' + port + '/tcp\n';

    concluded = get_kb_item("ibm/db2/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded: ' + concluded + '\n';

    fix_pack = get_kb_item("ibm/db2/ssh-login/" + port + "/fix_pack");

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

if (drda_ports = get_kb_list("ibm/db2/drda/port")) {
  foreach port (drda_ports) {
    extra += 'DRDA on port ' + port + '/tcp\n';

    concluded = get_kb_item("ibm/db2/drda/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "drda");
  }
}

if (das_ports = get_kb_list("ibm/db2/das/port")) {
  foreach port (das_ports) {
    extra += 'Db2 Administration Server (DAS) on port ' + port + '/udp\n';

    concluded = get_kb_item("ibm/db2/das/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "db2-das", proto: "udp");
  }
}

if (!isnull(concluded = get_kb_item("ibm/db2/smb/0/concluded"))) {
  extra += 'Local Detection over SMB:\n';
  extra += '  Concluded from:\n' + concluded;
  loc = get_kb_item("ibm/db2/smb/0/location");
  if (loc)
    extra += '\nLocation:       ' + loc;

  register_product(cpe: cpe, location: loc, port: 0, service: "smb-login");
}

report = build_detection_report(app: "IBM Db2", version: detected_version, install: location, cpe: cpe, patch: fix_pack);

if (extra) {
  report += '\n\nDetection methods:\n\n';
  report += extra;
}

log_message(port: 0, data: report);

exit(0);
