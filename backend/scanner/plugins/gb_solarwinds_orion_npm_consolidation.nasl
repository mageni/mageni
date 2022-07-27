# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.142006");
  script_version("$Revision: 13748 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 05:10:22 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-19 10:04:35 +0700 (Tue, 19 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SolarWinds Orion Network Performance Monitor Consolidation");

  script_tag(name:"summary", value:"The script reports a detected SolarWinds Orion Network Performance Monitor
including the version number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_orion_npm_detect.nasl", "gb_solarwinds_orion_npm_detect_win.nasl");
  script_mandatory_keys("solarwinds/orion/npm/detected");

  script_xref(name:"URL", value:"http://www.solarwinds.com/products/orion/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("solarwinds/orion/npm/detected"))
  exit(0);

detected_version = "unknown";

foreach source (make_list("win", "http")) {
  version_list = get_kb_list("solarwinds/orion/npm/" + source + "/*/version");
  foreach vers (version_list) {
    if (vers != "unknown" && detected_version == "unknown")
      detected_version = vers;
  }
}

# e.g. 9.5 SP2
cpe_vers = str_replace( string: detected_version, find: " ", replace: ".");
cpe = build_cpe(value: cpe_vers, exp: "^([0-9SP. ]+)",
                base: "cpe:/a:solarwinds:orion_network_performance_monitor:");
if (!cpe)
  cpe = 'cpe:/a:solarwinds:orion_network_performance_monitor';

if (http_ports = get_kb_list("solarwinds/orion/npm/http/port")) {
  if (!isnull(http_ports))
    extra += '\nRemote Detection over HTTP(s):\n';

  foreach port (http_ports) {
    concluded = get_kb_item("solarwinds/orion/npm/http/" + port + "/concluded");
    location =  get_kb_item("solarwinds/orion/npm/http/" + port + "/location");
    extra += '   Port:       ' + port + '/tcp\n';
    if (concluded)
      extra += '   Concluded:  ' + concluded + '\n';
    extra += '   Location:   ' + location + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (win_path = get_kb_item("solarwinds/orion/npm/win/path")) {
  extra += 'Local Detection on Windows:\n';
  extra += '   Path:       ' + win_path + '\n';

  register_product(cpe: cpe, location: win_path, port: 0, service: "smb-login");
}

report = build_detection_report(app: "SolarWinds Orion Network Performance Monitor", version: detected_version,
         cpe: cpe, install: "/", extra: extra);

if (report)
  log_message(port: 0, data: report);

exit(0);
