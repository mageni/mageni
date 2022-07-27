# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:opencast:opencast";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143446");
  script_version("2020-02-04T08:04:36+0000");
  script_tag(name:"last_modification", value:"2020-02-04 08:04:36 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-04 07:51:44 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");

  script_cve_id("CVE-2020-5206", "CVE-2020-5222", "CVE-2020-5228", "CVE-2020-5230", "CVE-2020-5231");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenCast < 7.6.0 and 8.0.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"OpenCast is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenCast is prone to multiple vulnerabilities:

  - Authentication Bypass For Endpoints With Anonymous Access (CVE-2020-5206)

  - Hard-Coded Key Used For Remember-me Token (CVE-2020-5222)

  - Unauthenticated Access Via OAI-PMH (CVE-2020-5228)

  - Unsafe Identifiers (CVE-2020-5230)

  - Users with ROLE_COURSE_ADMIN can create new users (CVE-2020-5231)");

  script_tag(name:"affected", value:"OpenCast versions prior to 7.6.0 and version 8.0.0.");

  script_tag(name:"solution", value:"Update to version 7.6.0, 8.1.0 or later.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-vmm6-w4cf-7f3x");
  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-mh8g-hprg-8363");
  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-6f54-3qr9-pjgj");
  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-w29m-fjp4-qhmq");
  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-94qw-r73x-j7hg");

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

if (version_is_less(version: version, test_version: "7.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
