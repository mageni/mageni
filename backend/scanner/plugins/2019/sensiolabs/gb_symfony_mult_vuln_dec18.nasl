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
  script_oid("1.3.6.1.4.1.25623.1.0.112583");
  script_version("2019-05-20T11:12:06+0000");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:06 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-20 11:50:54 +0200 (Mon, 20 May 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-19789", "CVE-2018-19790");
  script_bugtraq_id(106249);

  script_name("Symfony 2.7.x < 2.7.50, 2.8.x < 2.8.49, 3.x < 3.4.20, 4.0.x < 4.0.15, 4.x < 4.1.9, 4.2.x < 4.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"This host runs Symfony and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - When using the scalar type hint string in a setter method (e.g. setName(string $name)) of a class
  that's the data_class of a form, and when a file upload is submitted to the corresponding field
  instead of a normal text input, then UploadedFile::__toString() is called which will then return
  and disclose the path of the uploaded file. If combined with a local file inclusion issue in
  certain circumstances this could escalate it to a Remote Code Execution. (CVE-2018-19789)

  - Using backslashes in the _failure_path input field of login forms, one can work around the
  redirection target restrictions and effectively redirect the user to any domain after login. (CVE-2018-19790)");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to disclose
  the full path of an uploaded file, execute arbitrary code or redirect a user to any domain after login.");
  script_tag(name:"affected", value:"Symfony versions 2.7.0 to 2.7.49, 2.8.0 to 2.8.48, 3.0.0 to 3.4.19, 4.0.0 to 4.0.14, 4.1.0 to 4.1.8 and 4.2.0.");
  script_tag(name:"solution", value:"The issue has been fixed in Symfony 2.7.50, 2.8.49, 3.4.20, 4.0.15, 4.1.9 and 4.2.1.

  NOTE: No fixes are provided for Symfony 3.0, 3.1, 3.2 and 3.3 as they are not maintained anymore.
  It is recommended to upgrade to a supported version as soon as possible.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-19789-disclosure-of-uploaded-files-full-path");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-19790-open-redirect-vulnerability-when-using-security-http");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.7.0", test_version2: "2.7.49" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.50", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.48" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.49", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.4.19" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.20", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.15", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.1.0", test_version2: "4.1.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "4.2.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
