# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124282");
  script_version("2023-02-22T10:10:00+0000");
  script_tag(name:"last_modification", value:"2023-02-22 10:10:00 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-20 10:48:56 +0200 (Mon, 20 Feb 2023)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:P");

  script_cve_id("CVE-2023-0880");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpmyFAQ < 3.1.11 Improper Input Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to an improper input validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An Attacker can bypass all the required fields by sending a
  space at any required field like name, text, answer or question which is a required Point and
  send empty FAQ Proposals and spam, scan or due further malicious things.");

  script_tag(name:"affected", value:"phpMyFAQ versions prior to 3.1.11.");

  script_tag(name:"solution", value:"Update to version 3.1.11 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/14fc4841-0f5d-4e12-bf9e-1b60d2ac6a6c/");

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

if (version_is_less(version: version, test_version: "3.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
