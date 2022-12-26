# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126262");
  script_version("2022-12-23T08:11:00+0000");
  script_tag(name:"last_modification", value:"2022-12-23 08:11:00 +0000 (Fri, 23 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-20 10:46:57 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2022-4427");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: "Patch 1" not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Improper Input Validation Vulnerability (OSA-2022-15)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to an improper input validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper input validation vulnerability allows SQL injection
  via TicketSearch webservice.");

  script_tag(name:"affected", value:"OTRS version 6.0.x prior to 7.0.40 Patch 1 and 8.0.x prior to
  8.0.28 Patch 1.");

  script_tag(name:"solution", value:"Update to version 7.0.40 Patch 1, 8.0.28 Patch 1 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2022-15/");

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

if (version_in_range(version: version, test_version: "6.0", test_version2: "7.0.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.40 Patch 1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.28 Patch 1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

