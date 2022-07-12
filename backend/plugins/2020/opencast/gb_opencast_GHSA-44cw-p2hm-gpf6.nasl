# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:opencast:opencast";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145019");
  script_version("2020-12-10T07:42:55+0000");
  script_tag(name:"last_modification", value:"2020-12-10 07:42:55 +0000 (Thu, 10 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-10 07:35:23 +0000 (Thu, 10 Dec 2020)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:C/A:N");

  script_cve_id("CVE-2020-26234");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenCast < 7.9, 8.0 < 8.9 Hostname Verification Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"OpenCast is prone to a hostname verification vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Opencast disables HTTPS hostname verification of its HTTP client used for a
  large portion of Opencast's HTTP requests.

  Hostname verification is an important part when using HTTPS to ensure that the presented certificate is valid
  for the host. Disabling it can allow for man-in-the-middle attacks.");

  script_tag(name:"affected", value:"OpenCast versions prior to 7.9 and versions 8.0 - 8.8.");

  script_tag(name:"solution", value:"Update to version 7.9, 8.9 or later.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-44cw-p2hm-gpf6");

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

if (version_is_less(version: version, test_version: "7.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
