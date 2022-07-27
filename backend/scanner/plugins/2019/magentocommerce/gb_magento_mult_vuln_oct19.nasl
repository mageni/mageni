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
  script_oid("1.3.6.1.4.1.25623.1.0.112662");
  script_version("2019-11-07T14:40:22+0000");
  script_tag(name:"last_modification", value:"2019-11-07 14:40:22 +0000 (Thu, 07 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-07 13:16:45 +0000 (Thu, 07 Nov 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2019-8090", "CVE-2019-8092", "CVE-2019-8093", "CVE-2019-8107",
  "CVE-2019-8108", "CVE-2019-8109", "CVE-2019-8110", "CVE-2019-8111", "CVE-2019-8112",
  "CVE-2019-8113", "CVE-2019-8115", "CVE-2019-8116", "CVE-2019-8117", "CVE-2019-8118",
  "CVE-2019-8119", "CVE-2019-8120", "CVE-2019-8121", "CVE-2019-8122", "CVE-2019-8124",
  "CVE-2019-8126", "CVE-2019-8127", "CVE-2019-8128", "CVE-2019-8129", "CVE-2019-8130",
  "CVE-2019-8131", "CVE-2019-8132", "CVE-2019-8133", "CVE-2019-8134", "CVE-2019-8135",
  "CVE-2019-8136", "CVE-2019-8137", "CVE-2019-8138", "CVE-2019-8140", "CVE-2019-8141",
  "CVE-2019-8142", "CVE-2019-8143", "CVE-2019-8145", "CVE-2019-8146", "CVE-2019-8147",
  "CVE-2019-8149", "CVE-2019-8150", "CVE-2019-8151", "CVE-2019-8153", "CVE-2019-8154",
  "CVE-2019-8156", "CVE-2019-8157", "CVE-2019-8158", "CVE-2019-8159", "CVE-2019-8233");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # patch version not retrievable

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento 2.2.x < 2.2.10, 2.3.x < 2.3.3 or 2.3.2-p1 Multiple Vulnerabilities - October 19");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple vulnerabilities, including remote code execution (RCE),
  SQL injection, using components with known vulnerabilities, server-side request forgery (SSRF), arbitrary file deletion,
  XML external entity injection (XXE), cross-site scripting (XSS), information disclosure and others.

  See the referenced advisories for further details on each specific vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Magento 2.2 prior to 2.2.10, Magento 2.3 prior to 2.3.3 or 2.3.2-p1.");

  script_tag(name:"solution", value:"Update to version 2.2.10, 2.3.3 or later.");

  script_xref(name:"URL", value:"https://magento.com/security/patches/magento-2.3.3-and-2.2.10-security-update");

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

if(version_in_range(version: version, test_version: "2.2", test_version2: "2.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.10", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "2.3", test_version2: "2.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.3 or 2.3.2-p1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
