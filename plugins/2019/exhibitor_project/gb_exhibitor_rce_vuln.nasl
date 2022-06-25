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

CPE = "cpe:/a:exhibitor_project:exhibitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143181");
  script_version("2019-11-26T07:37:08+0000");
  script_tag(name:"last_modification", value:"2019-11-26 07:37:08 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-26 07:28:38 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-5029");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Exhibitor 1.0.9 <= 1.7.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_exhibitor_detect.nasl");
  script_mandatory_keys("exhibitor/detected");

  script_tag(name:"summary", value:"Exhibitor is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Arbitrary shell commands surrounded by backticks or $() can be inserted into
  the editor and will be executed by the Exhibitor process when it launches ZooKeeper. An attacker can execute any
  command as the user running the Exhibitor process.");

  script_tag(name:"affected", value:"Exhibitor versions 1.0.9 - 1.7.1.");

  script_tag(name:"solution", value:"No known solution is available as of 26th November, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2019-0790");

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

if (version_in_range(version: version, test_version: "1.0.9", test_version2: "1.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
