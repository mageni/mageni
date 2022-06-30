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

CPE = "cpe:/a:mahara:mahara";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.124087");
  script_version("2022-06-29T10:11:11+0000");
  script_tag(name:"last_modification", value:"2022-06-29 10:11:11 +0000 (Wed, 29 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-24 06:15:34 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 18:31:00 +0000 (Mon, 27 Jun 2022)");

  script_cve_id("CVE-2022-33913");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara 20.04.x < 21.04.6, 21.10.x < 21.10.4, 22.04.x < 22.04.2 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Files can sometimes be downloaded through thumb.php with no
  permission check.");

  script_tag(name:"affected", value:"Mahara version 20.04.x, 20.10.x, 21.04.x through 21.04.05,
  21.10.x through 21.10.03 and 22.04.x through 22.04.1.");

  script_tag(name:"solution", value:"Update to version 21.04.6, 21.10.4 and 22.04.2 or later.");

  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=9138");

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

if (version_in_range_exclusive(version: version, test_version_lo: "20.04.0", test_version_up: "21.04.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.04.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.10.0", test_version_up: "21.10.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.10.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "22.04.0", test_version_up: "22.04.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.04.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
