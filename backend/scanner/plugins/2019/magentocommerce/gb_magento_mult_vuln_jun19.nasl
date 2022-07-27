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

CPE = 'cpe:/a:magentocommerce:magento';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112598");
  script_version("2019-07-04T13:06:41+0000");
  script_tag(name:"last_modification", value:"2019-07-04 13:06:41 +0000 (Thu, 04 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-04 14:37:11 +0200 (Thu, 04 Jul 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2019-7895", "CVE-2019-7896", "CVE-2019-7930", "CVE-2019-7871", "CVE-2019-7942", "CVE-2019-7903",
 "CVE-2019-7931", "CVE-2019-7932", "CVE-2019-7885", "CVE-2019-7950", "CVE-2019-7904", "CVE-2019-7139", "CVE-2019-7928",
 "CVE-2019-7892", "CVE-2019-7876", "CVE-2019-7923", "CVE-2019-7913", "CVE-2019-7911", "CVE-2019-7951", "CVE-2019-7861",
 "CVE-2019-7915", "CVE-2019-7872", "CVE-2019-7874", "CVE-2019-7927", "CVE-2019-7936", "CVE-2019-7850", "CVE-2019-7862",
 "CVE-2019-7937", "CVE-2019-7889", "CVE-2019-7897", "CVE-2019-7909", "CVE-2019-7921", "CVE-2019-7875", "CVE-2019-7925",
 "CVE-2019-7926", "CVE-2019-7945", "CVE-2019-7908", "CVE-2019-7880", "CVE-2019-7877", "CVE-2019-7869", "CVE-2019-7868",
 "CVE-2019-7867", "CVE-2019-7866", "CVE-2019-7863", "CVE-2019-7934", "CVE-2019-7935", "CVE-2019-7938", "CVE-2019-7940",
 "CVE-2019-7944", "CVE-2019-7853", "CVE-2019-7859", "CVE-2019-7858", "CVE-2019-7855", "CVE-2019-7898", "CVE-2019-7890",
 "CVE-2019-7854", "CVE-2019-7887", "CVE-2019-7881", "CVE-2019-7882", "CVE-2019-7939", "CVE-2019-7888", "CVE-2019-7929",
 "CVE-2019-7899", "CVE-2019-7857", "CVE-2019-7873", "CVE-2019-7851", "CVE-2019-7860", "CVE-2019-7864", "CVE-2019-7886",
 "CVE-2019-7846", "CVE-2019-7852", "CVE-2019-7849", "CVE-2019-7947", "CVE-2019-7865", "CVE-2019-7912");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # patch version not retrievable

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento 2.1.x < 2.1.18, 2.2.x < 2.2.9, 2.3.x < 2.3.2 Multiple Vulnerabilities - June 19");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple vulnerabilities, including remote code execution (RCE),
  cross-site scripting (XSS) and others.

  See the referenced advisories for further details on each specific vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 2.1.18, 2.2.9, 2.3.2 or later.");

  script_xref(name:"URL", value:"https://magento.com/security/patches/magento-2.3.2-2.2.9-and-2.1.18-security-update-13");
  script_xref(name:"URL", value:"https://magento.com/security/patches/magento-2.3.2-2.2.9-and-2.1.18-security-update-23");
  script_xref(name:"URL", value:"https://magento.com/security/patches/magento-2.3.2-2.2.9-and-2.1.18-security-update-33");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if(version_in_range(version: version, test_version: "2.1", test_version2: "2.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.18", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "2.2", test_version2: "2.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.9", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "2.3", test_version2: "2.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
