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

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143548");
  script_version("2020-02-24T06:36:45+0000");
  script_tag(name:"last_modification", value:"2020-02-24 06:36:45 +0000 (Mon, 24 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-24 06:36:04 +0000 (Mon, 24 Feb 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-8813");

  script_name("Cacti < 1.2.10 RCE Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Cacti is prone to an authenticated remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"graph_realtime.php in Cacti allows remote attackers to execute arbitrary OS
  commands via shell metacharacters in a cookie, if a guest user has the graph real-time privilege.");

  script_tag(name:"affected", value:"Cacti prior to version 1.2.10.");

  script_tag(name:"solution", value:"Update to version 1.2.10 or later.");

  script_xref(name:"URL", value:"https://shells.systems/cacti-v1-2-8-authenticated-remote-code-execution-cve-2020-8813/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.10", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
