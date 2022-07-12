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

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143428");
  script_version("2020-01-30T05:14:26+0000");
  script_tag(name:"last_modification", value:"2020-01-30 05:14:26 +0000 (Thu, 30 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-30 04:43:58 +0000 (Thu, 30 Jan 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-3715", "CVE-2020-3716", "CVE-2020-3717", "CVE-2020-3718", "CVE-2020-3719",
                "CVE-2020-3758");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento Multiple Vulnerabilities (APSB20-02)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Magento is prone to multiple vulnerabilities:

  - Multiple stored XSS vulnerabilities (CVE-2020-3715, CVE-2020-3758)

  - Deserialization of untrusted data leading to remote code execution (CVE-2020-3716)

  - Path traversal vulnerability (CVE-2020-3717)

  - Security bypass leading to remote code execution (CVE-2020-3718)

  - SQL injection vulnerability (CVE-2020-3719)");

  script_tag(name:"affected", value:"Magento versions 1.9.4.3 and prior, 1.14.4.3 and prior, 2.2.10 and prior and
  2.3.3 and prior.");

  script_tag(name:"solution", value:"Update to version 1.9.4.4, 1.14.4.4, 2.2.11, 2.3.4 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/magento/apsb20-02.html");

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

if (version_is_less(version: version, test_version: "1.9.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "1.10", test_version2: "1.14.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "2.0", test_version2: "2.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "2.3", test_version2: "2.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
