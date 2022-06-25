###############################################################################
# OpenVAS Vulnerability Test
#
# Sensiolabs Symfony 2.8.x < 2.8.37, 3.3.x < 3.3.17, 3.4.x < 3.4.7 and 4.0.x < 4.0.7 Authentication Bypass Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112434");
  script_version("2019-05-20T11:07:17+0000");
  script_tag(name:"last_modification", value:"2019-05-20 11:07:17 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-20 15:02:11 +0100 (Tue, 20 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11407");

  script_name("Sensiolabs Symfony 2.8.x < 2.8.37, 3.3.x < 3.3.17, 3.4.x < 3.4.7 and 4.0.x < 4.0.7 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"This host runs Symfony and is prone to an authentication bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An issue was discovered in the Ldap component in Symfony.
  It allows remote attackers to bypass authentication by logging in with a 'null' password and valid username,
  which triggers an unauthenticated bind.

  NOTE: this issue exists because of an incomplete fix for CVE-2016-2403.");
  script_tag(name:"affected", value:"Symfony versions 2.8.0 to 2.8.36, 3.3.0 to 3.3.16, 3.4.0 to 3.4.6 and 4.0.0 to 4.0.6.");
  script_tag(name:"solution", value:"The issue has been fixed in Symfony 2.8.37, 3.3.17, 3.4.7 and 4.0.7.

  NOTE: No fixes are provided for Symfony 3.0, 3.1, and 3.2 as they are not maintained anymore.
  It is recommended to upgrade to a supported version.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-11407-unauthorized-access-on-a-misconfigured-ldap-server-when-using-an-empty-password");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.36" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.37", install_path: location);
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.3.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.17", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
