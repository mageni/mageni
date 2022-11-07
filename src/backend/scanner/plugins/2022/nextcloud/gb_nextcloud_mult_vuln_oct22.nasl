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
  script_oid("1.3.6.1.4.1.25623.1.0.127235");
  script_version("2022-11-03T10:20:15+0000");
  script_tag(name:"last_modification", value:"2022-11-03 10:20:15 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-10-31 09:11:11 +0000 (Mon, 31 Oct 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2022-39329", "CVE-2022-39364");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 23.0.9, < 24.0.5 Multiple Information Disclosure Vulnerabilities (GHSA-8f3p-rcm5-mrg3, GHSA-qpf5-jj85-36h5)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple information disclosure
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2022-39329: Exposure of information that can not be controlled by administrators without
  direct database access.

  - CVE-2022-39364: When an attacker gets hold of the nextcloud.log, they may gain knowledge of
  credentials to connect to a SharePoint service.");

  script_tag(name:"affected", value:"Nextcloud server prior to version 23.0.9 and 24.0.5.");

  script_tag(name:"solution", value:"Update to version 23.0.9, 24.0.5 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-8f3p-rcm5-mrg3");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-qpf5-jj85-36h5");

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

if (version_is_less(version: version, test_version: "23.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_less(version: version, test_version: "24.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
