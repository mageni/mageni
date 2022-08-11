# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142612");
  script_version("2019-07-22T13:49:29+0000");
  script_tag(name:"last_modification", value:"2019-07-22 13:49:29 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-18 06:43:54 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Hudson CI Consolidation");

  script_tag(name:"summary", value:"The script reports a detected Hudson CI including the version number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sw_hudson_detect.nasl", "gb_hudson_udp_detect.nasl");

  script_mandatory_keys("hudson/detected");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("hudson/detected"))
  exit(0);

report = "";

if (http_ports = get_kb_list("hudson/http/port")) {
  http_ports = sort(http_ports);

  foreach port (http_ports) {
    version = get_kb_item("hudson/http/" + port + "/version");
    if (!version)
      version = "unknown";
    else
      concl = get_kb_item("hudson/http/" + port + "/concluded");

    location = get_kb_item("hudson/http/" + port + "/location");

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:oracle:hudson:");
    if (!cpe)
      cpe = "cpe:/a:oracle:hudson";

    register_product(cpe: cpe, location: location, port: port, service: "www");

    if (report)
      report += '\n\n';

    report += build_detection_report(app: "Hudson CI", version: version, install: location, cpe: cpe,
                                     concluded: concl, extra: "Detected on HTTP(S) port " + port + "/tcp");
  }
}

if (disc_ports = get_kb_list("hudson/autodiscovery/port")) {
  disc_ports = sort(disc_ports);

  foreach port (disc_ports) {

    version = get_kb_item("hudson/autodiscovery/" + port + "/version");
    concl = get_kb_item("hudson/autodiscovery/" + port + "/concluded");

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:oracle:hudson:");
    if (!cpe)
      cpe = "cpe:/a:oracle:hudson";

    register_product(cpe: cpe, location: "/", port: port, proto: "udp", service: "hudson-autodiscovery");

    if (report)
      report += '\n\n\n';

    report += build_detection_report(app: "Hudson CI (Auto-Discovery)", version: version,
                                     install: "/", cpe: cpe, concluded: concl,
                                     extra: "Detected on auto-discovery port " + port + "/udp");
  }
}

log_message(port: 0, data: report);

exit(0);
