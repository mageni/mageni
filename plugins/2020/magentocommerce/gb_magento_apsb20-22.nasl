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

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143808");
  script_version("2020-05-04T03:14:57+0000");
  script_tag(name:"last_modification", value:"2020-05-04 03:14:57 +0000 (Mon, 04 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-04 03:02:47 +0000 (Mon, 04 May 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-9576", "CVE-2020-9577", "CVE-2020-9578", "CVE-2020-9579", "CVE-2020-9580",
                "CVE-2020-9581", "CVE-2020-9582", "CVE-2020-9583", "CVE-2020-9584", "CVE-2020-9585",
                "CVE-2020-9587", "CVE-2020-9588", "CVE-2020-9591");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento Multiple Vulnerabilities (ASPB20-22)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Magento is prone to multiple vulnerabilities:

  - Multiple command injection vulnerabilities (CVE-2020-9576, CVE-2020-9578, CVE-2020-9582, CVE-2020-9583)

  - Multiple cross-site scripting vulnerabilities (CVE-2020-9577, CVE-2020-9581, CVE-2020-9584)

  - Multiple security mitigation bypass vulnerabilities (CVE-2020-9579, CVE-2020-9580, )

  - Arbitrary code execution vulnerability (CVE-2020-9585)

  - Unauthorized access to admin panel (CVE-2020-9591)

  - Potentially unauthorized product discounts (CVE-2020-9587)

  - Signature verification bypass vulnerability (CVE-2020-9588)");

  script_tag(name:"affected", value:"Magento versions 1.9.4.4 and prior, 1.14.4.4 and prior, 2.2.11 and prior and
  2.3.4 and prior.");

  script_tag(name:"solution", value:"Update to version 1.9.4.5, 1.14.4.5, 2.3.4-p2 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/magento/apsb20-22.html");

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

if (version_is_less(version: version, test_version: "1.9.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "1.10", test_version2: "1.14.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "2.0", test_version2: "2.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.4-p2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "2.3", test_version2: "2.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.4-p2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
