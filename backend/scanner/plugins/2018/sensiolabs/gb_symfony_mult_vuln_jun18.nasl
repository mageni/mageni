###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symfony_mult_vuln_jun18.nasl 12442 2018-11-20 14:05:57Z asteins $
#
# Sensiolabs Symfony 2.7.x < 2.7.48, 2.8.x < 2.8.41, 3.3.x < 3.3.17, 3.4.x < 3.4.11, and 4.0.x < 4.0.11 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.112433");
  script_version("$Revision: 12442 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 15:05:57 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-20 14:53:12 +0100 (Tue, 20 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11385", "CVE-2018-11386", "CVE-2018-11406", "CVE-2018-11408");

  script_name("Sensiolabs Symfony 2.7.x < 2.7.48, 2.8.x < 2.8.41, 3.3.x < 3.3.17, 3.4.x < 3.4.11, and 4.0.x < 4.0.11 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"This host runs Symfony and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A session fixation vulnerability within the 'Guard' login feature may allow an attacker to impersonate
  a victim towards the web application if the session id value was previously known to the attacker. (CVE-2018-11385)

  - The PDOSessionHandler class allows storing sessions on a PDO connection. Under some configurations
  and with a well-crafted payload, it was possible to do a denial of service on a Symfony application without too much resources.
  (CVE-2018-11386)

  - By default, a user's session is invalidated when the user is logged out. This behavior can be disabled
  through the invalidate_session option. In this case, CSRF tokens were not erased during logout which allowed for CSRF token fixation.
  (CVE-2018-11406)

  - The security handlers in the Security component in Symfony have an Open redirect vulnerability
  when security.http_utils is inlined by a container. NOTE: this issue exists because of an incomplete fix for CVE-2017-16652.
  (CVE-2018-11408)");
  script_tag(name:"affected", value:"Symfony versions 2.7.0 to 2.7.47, 2.8.0 to 2.8.40, 3.3.0 to 3.3.16, 3.4.0 to 3.4.10 and 4.0.0 to 4.0.10");
  script_tag(name:"solution", value:"The issue has been fixed in Symfony 2.7.48, 2.8.41, 3.3.17, 3.4.11 and 4.0.11.

  NOTE: No fixes are provided for Symfony 3.0, 3.1, and 3.2 as they are not maintained anymore.
  It is recommended to upgrade to a supported version.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-11385-session-fixation-issue-for-guard-authentication");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-11386-denial-of-service-when-using-pdosessionhandler");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-11406-csrf-token-fixation");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-11408-open-redirect-vulnerability-on-security-handlers");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.7.0", test_version2: "2.7.47" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.48", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.40" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.41", install_path: location);
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.3.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.17", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.11", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.11", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
