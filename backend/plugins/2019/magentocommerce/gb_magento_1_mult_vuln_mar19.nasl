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
  script_oid("1.3.6.1.4.1.25623.1.0.142212");
  script_version("2019-03-29T12:36:57+0000");
  script_tag(name:"last_modification", value:"2019-03-29 12:36:57 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-29 10:17:27 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento 1.x Multiple Vulnerabilities - March19");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento 1.x is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Magento 1.x is prone to multiple vulnerabilities:

  - SQL Injection vulnerability through an unauthenticated user

  - Remote code execution via server side request forgery issued to Redis

  - Arbitrary code execution due to unsafe handling of a malicious product attribute configuration

  - Arbitrary code execution due to unsafe deserialization of a PHP archive

  - Arbitrary code execution due to unsafe handling of a malicious layout update

  - Remote code execution through PHP code that can be uploaded to the ngnix server due to crafted customer store
    attributes

  - Remote code execution through arbitrary XML data sent through a layout table

  - Arbitrary code execution through bypass of PHP file upload restriction

  - Arbitrary code execution due to bypass of layout validator

  - Stored cross-site scripting in the escaper framework

  - Reflected cross-site scriptingin the product widget chooser section of the Admin

  - Deletion of Catalog rules through  cross-site request forgery

  - Deletion of Catalog products through  cross-site request forgery

  - Stored cross-site scripting in the admin panel via the Admin Shopping Cart Rules page

  - Deletion of SOAP/XML-RPC-User and SOAP/XML-RPC-Role through cross-site request forgery

  - Deletion of user roles through cross-site request forgery

  - Deletion of store design schedule through cross-site request forgery

  - Deletion of shopping cart price rules through cross-site request forgery

  - Deletion of REST-Role and REST-OAuth Consumer, and change of REST-Attribute via cross-site request forgery

  - Deletion of a product attribute through cross-site request forgery

  - Deletion of an Admin user through cross-site request forgery

  - Stored cross-site scripting in the Admin through the Email Template Preview section

  - Data manipulation due to improper validation

  - Admin credentials are logged in exception reports

  - Unauthorized access to the order list through an insecure direct object reference in the application");

  script_tag(name:"solution", value:"Update to version 1.9.4.1, 1.14.4.1 or later.");

  script_xref(name:"URL", value:"https://magento.com/security/patches/supee-11086");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (get_kb_item("magento/CE/installed")) {
  if (version_in_range(version: version, test_version: "1.5.0.0", test_version2: "1.9.4.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.9.4.1", install_path: path);
    security_message(port: port, data: report);
    exit(0);
  }
}
else {
  if (version_in_range(version: version, test_version: "1.9.0.0", test_version2: "1.14.4.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.14.4.1", install_path: path);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
