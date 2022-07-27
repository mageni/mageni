# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112581");
  script_version("2019-05-20T11:12:06+0000");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:06 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-20 11:27:12 +0200 (Mon, 20 May 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10909", "CVE-2019-10910", "CVE-2019-10911", "CVE-2019-10913");

  script_name("Symfony 2.7.x < 2.7.51, 2.8.x < 2.8.50, 3.x < 3.4.26, 4.x < 4.1.12, 4.2.x < 4.2.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"This host runs Symfony and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Validation messages were not escaped when using the form theme of the PHP templating engine which,
  when validation messages may contain user input, could result in an XSS. (CVE-2019-10909)

  - Service IDs derived from unfiltered user input could result in the execution of any arbitrary code,
  resulting in possible remote code execution. (CVE-2019-10910)

  - A vulnerability would allow an attacker to authenticate as a privileged user on sites with user
  registration and remember me login functionality enabled. (CVE-2019-10911)

  - HTTP methods, from either the HTTP method itself or using the X-Http-Method-Override header
  were previously returned as the method in question without validation being done on the string,
  meaning that they could be used in dangerous contexts when left unescaped. (CVE-2019-10913)");
  script_tag(name:"impact", value:"Successful exploitation could lead to cross-site scripting (XSS),
  SQL injection, remote code execution and the attacker being able to authenticate as a privileged user.");
  script_tag(name:"affected", value:"Symfony versions 2.7.0 to 2.7.50, 2.8.0 to 2.8.49, 3.4.0 to 3.4.25,
  4.1.0 to 4.1.11 and 4.2.0 to 4.2.6.");
  script_tag(name:"solution", value:"The issue has been fixed in Symfony 2.7.51, 2.8.50, 3.4.26, 4.1.12 and 4.2.7.

  NOTE: No fixes are provided for Symfony 3.0, 3.1, 3.2, 3.3, and 4.0 as they are not maintained anymore.
  It is recommended to upgrade to a supported version as soon as possible.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-10909-escape-validation-messages-in-the-php-templating-engine");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-10910-check-service-ids-are-valid");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-10911-add-a-separator-in-the-remember-me-cookie-hash");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-10913-reject-invalid-http-method-overrides");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-005");
  script_xref(name:"URL", value:"https://github.com/symfony/symfony/commit/ab4d05358c3d0dd1a36fc8c306829f68e3dd84e2");
  script_xref(name:"URL", value:"https://github.com/symfony/symfony/commit/d2fb5893923292a1da7985f0b56960b5bb10737b");
  script_xref(name:"URL", value:"https://github.com/symfony/symfony/commit/a29ce2817cf43bb1850cf6af114004ac26c7a081");
  script_xref(name:"URL", value:"https://github.com/symfony/symfony/commit/944e60f083c3bffbc6a0b5112db127a10a66a8ec");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.7.0", test_version2: "2.7.50" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.51", install_path: location);
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.49" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.50", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.4.25" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.26", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.0.0", test_version2: "4.1.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.12", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.2.0", test_version2: "4.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
