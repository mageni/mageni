# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112717");
  script_version("2020-03-24T11:42:50+0000");
  script_tag(name:"last_modification", value:"2020-03-25 11:04:45 +0000 (Wed, 25 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-24 11:38:05 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2019-16375");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 5.0.x < 5.0.38, 6.0.x < 6.0.23, 7.0.x < 7.0.12 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker who is logged into OTRS as an agent or customer user
  with appropriate permissions can create a carefully crafted string containing malicious JavaScript
  code as an article body. This malicious code is executed when an agent compose an answer to the original article.");

  script_tag(name:"affected", value:"OTRS 5.0.x through 5.0.37, 6.0.x through 6.0.22 and 7.0.x through 7.0.11.");

  script_tag(name:"solution", value:"Update to version 5.0.38, 6.0.23 or 7.0.12 respectively.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2019-13/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
