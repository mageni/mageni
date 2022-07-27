# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.146063");
  script_version("2021-06-02T08:32:19+0000");
  script_tag(name:"last_modification", value:"2021-06-02 10:30:49 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-02 08:13:18 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2021-32653", "CVE-2021-32654", "CVE-2021-32655");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Multiple Vulnerabilities (GHSA-396j-vqpr-qg45, GHSA-jf9h-v24c-22g5, GHSA-grph-cm44-p3jv)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-32653: Default settings leak federated cloud ID to lookup server of all users

  - CVE-2021-32654: Attacker can obtain write access to any federated share/public link

  - CVE-2021-32655: Files Drop public link can be added as federated share");

  script_tag(name:"affected", value:"Nextcloud server prior to versions 19.0.11, 20.0.10 or 21.0.2.");

  script_tag(name:"solution", value:"Update to version 19.0.11, 20.0.10 or 21.0.2 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-396j-vqpr-qg45");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-jf9h-v24c-22g5");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-grph-cm44-p3jv");

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

if (version_is_less(version: version, test_version: "19.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "20.0", test_version2: "20.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "21.0", test_version2: "21.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
