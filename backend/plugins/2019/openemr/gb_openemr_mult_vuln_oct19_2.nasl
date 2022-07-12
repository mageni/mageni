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

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143071");
  script_version("2019-10-28T07:44:21+0000");
  script_tag(name:"last_modification", value:"2019-10-28 07:44:21 +0000 (Mon, 28 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-28 07:32:46 +0000 (Mon, 28 Oct 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-16404", "CVE-2019-16862", "CVE-2019-17409");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR < 5.0.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenEMR is prone to multiple vulnerabilities:

  - Authenticated SQL Injection in interface/forms/eye_mag/js/eye_base.php (CVE-2019-16404)

  - Reflected XSS in interface/forms/eye_mag/view.php (CVE-2019-16862, CVE-2019-17409)");

  script_tag(name:"affected", value:"OpenEMR versions 5.0.1 - 5.0.2.");

  script_tag(name:"solution", value:"Update to version 5.0.2.1 or later.");

  script_xref(name:"URL", value:"https://github.com/lodestone-security/CVEs/blob/master/CVE-2019-16404/README.md");
  script_xref(name:"URL", value:"https://github.com/lodestone-security/CVEs/blob/master/CVE-2019-16862/README.md");
  script_xref(name:"URL", value:"https://github.com/lodestone-security/CVEs/blob/master/CVE-2019-17409/README.md");

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

if (version_in_range(version: version, test_version: "5.0.1", test_version2: "5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
