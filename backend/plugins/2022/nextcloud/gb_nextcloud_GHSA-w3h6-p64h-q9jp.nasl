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

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148160");
  script_version("2022-05-23T14:45:16+0000");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-23 04:02:40 +0000 (Mon, 23 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 18:01:00 +0000 (Fri, 06 May 2022)");

  script_cve_id("CVE-2022-24888");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 20.0.14.4, 21.x < 21.0.8, 22.x < 22.2.4, 23.x < 23.0.1 Control Character Filtering Vulnerability (GHSA-w3h6-p64h-q9jp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a control character filtering
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"It is possible to create files and folders that have leading and
  trailing \n, \r, \t, and \v characters. The server rejects files and folders that have these
  characters in the middle of their names, so this might be an opportunity for injection.");

  script_tag(name:"affected", value:"Nextcloud server prior to version 20.0.14.4, version 21.x
  through 21.0.7, 23.x through 22.2.3 and version 23.0.0.");

  script_tag(name:"solution", value:"Update to version 20.0.14.4, 21.0.8, 22.2.4, 23.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-w3h6-p64h-q9jp");

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

if (version_is_less(version: version, test_version: "20.0.14.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.14.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "21.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "22.0", test_version_up: "22.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "23.0", test_version_up: "23.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
