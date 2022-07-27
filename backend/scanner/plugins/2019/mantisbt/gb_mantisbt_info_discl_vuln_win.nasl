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

CPE = 'cpe:/a:mantisbt:mantisbt';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142172");
  script_version("2019-06-25T08:09:59+0000");
  script_tag(name:"last_modification", value:"2019-06-25 08:09:59 +0000 (Tue, 25 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-25 08:09:24 +0000 (Tue, 25 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2018-9839");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MantisBT < 2.13.2 Information Disclosure Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MantisBT is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Using a crafted request on bug_report_page.php (modifying the 'm_id'
  parameter), any user with REPORTER access or above is able to view any private issue's details (summary,
  description, steps to reproduce, additional information) when cloning it. By checking the 'Copy issue notes'
  and 'Copy attachments' checkboxes and completing the clone operation, this data also becomes public (except
  private notes).");

  script_tag(name:"affected", value:"MantisBT versions 1.3.0 through 2.13.1.");

  script_tag(name:"solution", value:"Update to version 2.13.2 or later.");

  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=24221");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "1.3.0", test_version2: "2.13.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.13.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
